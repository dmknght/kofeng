/*
 * hostile_lifetime - who owns what, in which order, and whether two instances of
 * the library can run side by side.
 *
 *   free rules       every product the caller frees is freed through ONE function,
 *                    and that function leaves the struct empty: a second call is a
 *                    no-op, not a double free (kgenome_funcs_free, _pe_imptab_free,
 *                    _elf_reloc_table_free); a NULL is ignored where the lib's own
 *                    siblings ignore it. Run under ASAN, which is what turns a
 *                    double free or a use after free into a report.
 *   borrowed buffers the bytes an emulator hands out (written runs, snapshots) are
 *                    valid until the emulator is freed, and walking again does not
 *                    move them (CLAUDE.md: a pointer a lib hands out has a stated lifetime).
 *   wrong order      calls made in an order no honest caller uses - run after a stop,
 *                    map after a run, fork after a run, a free of the source before
 *                    the copy, a query before a sweep - answer or refuse; none faults.
 *   NULL handles     the diagnose scan's accessors and the capability tables with the
 *                    argument a caller who ignored a failed allocation would pass.
 *   threads          "no writable global state" (kgenome.h) is a claim about the build,
 *                    and the way to hold it is to run it: eight threads each build and
 *                    analyse their own objects - decoders (the lazily built ARM, Thumb
 *                    and A64 tables are the one exception the header names: the threads
 *                    start together on a cold table), emulator, parsers, sweeps - and
 *                    every thread's result must equal the single-threaded one.
 */

#include "hk.h"

#include <kgenome.h>
#include <genotype/x86/x86.h>
#include <genotype/arm32/arm32.h>
#include <genotype/arm32/thumb.h>
#include <genotype/arm64/arm64.h>

#include <pthread.h>

#include "../../unit/known_miss.h"

/* ---- 1: the free rules ---------------------------------------------------------------------------- */

static int free_twice_funcs(void *arg)
{
	struct kgenome_func_set s;
	struct kgenome_func f = { 1, 2, 3, 4 };

	(void)arg;
	memset(&s, 0, sizeof s);
	s.v = malloc(sizeof f);
	if (!s.v)
		return 2;
	memcpy(s.v, &f, sizeof f);
	s.n = 1;
	kgenome_funcs_free(&s);
	if (s.v || s.n)
		return 1;
	kgenome_funcs_free(&s);               /* nothing left to free */
	kgenome_funcs_free(&s);
	return 0;
}

static int free_null_funcs(void *arg)
{
	(void)arg;
	kgenome_funcs_free(NULL);
	return 0;
}

static int free_twice_imptab(void *arg)
{
	static struct hk_pe pe;
	static struct kgenome_pe_info pi;
	struct kgenome_obj o;
	struct kgenome_pe_imptab t;
	kof_buf f;

	(void)arg;
	hk_pe(&pe, 0);
	f = kof_buf_make(pe.b, pe.n);
	if (!kgenome_pe_image_parse(f, &pi, &o))
		return 2;
	kgenome_pe_imptab_build(f, &pi, &t);
	if (!t.v)
		return 3;
	kgenome_pe_imptab_free(&t);
	kgenome_pe_imptab_free(&t);
	kgenome_pe_imptab_free(NULL);
	/* build again over the freed struct: no stale pointer is freed or reused */
	kgenome_pe_imptab_build(f, &pi, &t);
	kgenome_pe_imptab_free(&t);
	return t.v == NULL && t.n == 0 ? 0 : 1;
}

static int free_twice_relocs(void *arg)
{
	static struct hk_elf e;
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_elf_relocs rt;
	kof_buf f;

	(void)arg;
	hk_elf(&e, 1, 0, 1);
	f = kof_buf_make(e.b, e.n);
	if (!kgenome_elf_image_parse(f, &ei, &o))
		return 2;
	if (kgenome_elf_reloc_table(f, &ei, KGENOME_ELF_RELOC_CODE | KGENOME_ELF_RELOC_DATA, &rt) == 0)
		return 3;
	kgenome_elf_reloc_table_free(&rt);
	kgenome_elf_reloc_table_free(&rt);
	kgenome_elf_reloc_table_free(NULL);
	/* a table asked for over a struct that holds a stale pointer starts empty (out is overwritten) */
	rt.v = (struct kgenome_elf_reloc *)(uintptr_t)0x10;
	rt.n = 99;
	(void)kgenome_elf_reloc_table(f, &ei, KGENOME_ELF_RELOC_CODE, &rt);
	kgenome_elf_reloc_table_free(&rt);
	return rt.v == NULL ? 0 : 1;
}

static int free_misc_null(void *arg)
{
	(void)arg;
	kgenome_emu_free(NULL);
	kgenome_xref_free(NULL);
	kgenome_diag_scan_free(NULL);
	kgenome_diag_walk_free(NULL);
	kgenome_diag_apihash_free(NULL);
	return 0;
}

static int free_unmap_ownership(void *arg)
{
	static struct hk_pe pe;
	uint8_t *out = NULL;
	uint64_t len = 0xdead;
	struct kgenome_pe_unmap_info ui;
	kof_buf img;

	(void)arg;
	/* not a mapped PE: zero, and *out / *out_len are untouched */
	{
		static const uint8_t junk[64] = { 'M', 'Z' };
		if (kgenome_pe_unmap(kof_buf_make(junk, sizeof junk), 0x10000, 0, 1u << 20, &out, &len, &ui) != 0)
			return 1;
		if (out != NULL || len != 0xdead)
			return 2;
	}
	/* a mapped image (the file laid out by RVA): a malloc'd file the caller owns */
	hk_pe(&pe, 1);
	{
		static uint8_t mapped[0x4000];
		unsigned i;
		memset(mapped, 0, sizeof mapped);
		memcpy(mapped, pe.b, 0x200);                          /* headers */
		for (i = 0; i < 3; i++) {
			const uint8_t *s = pe.b + pe.sec + 40u * i;
			uint32_t rva = (uint32_t)hk_r(s + 12, 4, 0), raw = (uint32_t)hk_r(s + 20, 4, 0);
			memcpy(mapped + rva, pe.b + raw, 0x200);
		}
		img = kof_buf_make(mapped, sizeof mapped);
		if (kgenome_pe_unmap(img, 0x140000000ull, 0x140000000ull, 1u << 20, &out, &len, &ui) != 1)
			return 3;
		if (!out || len == 0 || len > (1u << 20))
			return 4;
		if (memcmp(out, "MZ", 2))
			return 5;
		free(out);                                        /* the caller's, with plain free */
		out = NULL;
		/* a cap too small: refused, out untouched */
		len = 0xdead;
		if (kgenome_pe_unmap(img, 0x140000000ull, 0x140000000ull, 16, &out, &len, NULL) != 0)
			return 6;
		if (out != NULL || len != 0xdead)
			return 7;
	}
	return 0;
}

static void t_free_rules(void)
{
	int sig = 0;

	CK(hk_isolated(free_twice_funcs, NULL, 10, &sig) == HK_OK);
	CK(hk_isolated(free_twice_imptab, NULL, 10, &sig) == HK_OK);
	CK(hk_isolated(free_twice_relocs, NULL, 10, &sig) == HK_OK);
	CK(hk_isolated(free_misc_null, NULL, 10, &sig) == HK_OK);
	CK(hk_isolated(free_unmap_ownership, NULL, 10, &sig) == HK_OK);
	CK(hk_isolated(free_null_funcs, NULL, 10, &sig) == HK_OK);   /* kgenome_funcs_free(NULL) faults while kgenome_pe_imptab_free, kgenome_elf_reloc_table_free, kgenome_diag_apihash_free, kgenome_xref_free and kgenome_emu_free ignore NULL */
}

/* ---- 2: borrowed buffers ------------------------------------------------------------------------------ */

/* mov rdi, DATA ; mov rcx, 4 ; L: mov [rdi], rcx ; add rdi, 0x1000 ; dec rcx ; jnz L ; hlt  (four pages written) */
static const uint8_t pages4[] = {
	0x48, 0xbf, 0, 0, 0x60, 0, 0, 0, 0, 0,
	0x48, 0xc7, 0xc1, 4, 0, 0, 0,
	0x48, 0x89, 0x0f,
	0x48, 0x81, 0xc7, 0, 0x10, 0, 0,
	0x48, 0xff, 0xc9,
	0x75, 0xf2,
	0xf4
};

static struct kgenome_emu *run_pages4(void)
{
	struct kgenome_emu_cfg cfg = { 10000, 64, 0, 0 };
	struct kgenome_emu *e = kgenome_emu_new(&cfg);

	kgenome_emu_map(e, 0x400000, pages4, sizeof pages4, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, 0x600000, NULL, 0, 0x8000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, 0x7ff00000, NULL, 0, 0x4000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, 0x400000);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, 0x7ff02000);
	(void)kgenome_emu_run(e);
	return e;
}

/* emu.h: "The bytes stay owned by the emulator and are valid until it is freed." */
static int borrowed_lifetime_case(void *arg)
{
	struct kgenome_emu *e = run_pages4();
	uint32_t it = 0;
	uint64_t va, len, v2, l2;
	const uint8_t *b1, *b2;
	uint8_t first;
	int rc;

	(void)arg;
	if (!kgenome_emu_next_written(e, &it, &va, &b1, &len) || !len)
		return 2;
	first = b1[0];
	/* the second call, and a walk from the top again: the first run's bytes must still be there */
	it = 0xfffffff0u;
	(void)kgenome_emu_next_written(e, &it, &v2, &b2, &l2);
	it = 1;
	(void)kgenome_emu_next_written(e, &it, &v2, &b2, &l2);
	rc = b1[0] == first ? 0 : 1;               /* (a freed buffer is a use after free here) */
	kgenome_emu_free(e);
	return rc;
}

/* a walk, more running, a walk: the second walk lists every page the run has written */
static int stale_walk_case(void *arg)
{
	/* mov byte [0x600000],1 ; nop ; mov byte [0x602000],2 ; hlt */
	static const uint8_t c[] = { 0xc6, 0x04, 0x25, 0, 0, 0x60, 0, 1, 0x90,
				     0xc6, 0x04, 0x25, 0, 0x20, 0x60, 0, 2, 0xf4 };
	struct kgenome_emu_cfg cfg = { 2, 64, 0, 0 };
	struct kgenome_emu *e = kgenome_emu_new(&cfg);
	uint32_t it = 0, n = 0;
	uint64_t va, len;
	const uint8_t *b;

	(void)arg;
	kgenome_emu_map(e, 0x400000, c, sizeof c, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, 0x600000, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, 0x602000, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_rip(e, 0x400000);
	(void)kgenome_emu_run(e);                     /* budget 2: the first store and the nop */
	while (kgenome_emu_next_written(e, &it, &va, &b, &len))
		n++;
	if (n != 1)
		return 2;
	kgenome_emu_set_max_insn(e, 100);
	(void)kgenome_emu_run(e);                     /* and now the second store */
	for (it = 0, n = 0; kgenome_emu_next_written(e, &it, &va, &b, &len); )
		n++;
	kgenome_emu_free(e);
	return n == 2 ? 0 : 1;
}

static void t_borrowed_buffers(void)
{
	struct kgenome_emu *e = run_pages4();
	uint32_t it = 0, n = 0, again;
	uint64_t va[8], len[8], v2, l2;
	const uint8_t *b2;
	uint8_t copy[8][32];
	unsigned i;
	int sig = 0;

	/* by VALUE the walk is repeatable: the same runs, the same bytes, as often as it is asked */
	while (n < 8 && kgenome_emu_next_written(e, &it, &va[n], &b2, &len[n])) {
		memcpy(copy[n], b2, len[n] < 32 ? len[n] : 32);
		n++;
	}
	CK(n >= 1);
	for (again = 0; again < 3; again++) {
		it = 0;
		for (i = 0; kgenome_emu_next_written(e, &it, &v2, &b2, &l2) && i < n; i++) {
			CK(v2 == va[i] && l2 == len[i]);
			CK(!memcmp(b2, copy[i], len[i] < 32 ? len[i] : 32));
		}
	}
	/* an iterator past the end stays ended, and a huge one is "no more" */
	it = 0xffffffffu;
	CK(kgenome_emu_next_written(e, &it, &v2, &b2, &l2) == 0);
	it = 0x7fffffffu;
	CK(kgenome_emu_next_snapshot(e, &it, &v2, &b2, &l2) == 0);
	/* a walk dropped half way, and one begun again, leave nothing dangling */
	it = 0;
	(void)kgenome_emu_next_written(e, &it, &v2, &b2, &l2);
	it = 0;
	(void)kgenome_emu_next_snapshot(e, &it, &v2, &b2, &l2);
	/* wrong order, all of it with an emulator that has run */
	CK(kgenome_emu_fork(e) == NULL);
	CK(kgenome_emu_map(e, 0x900000, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W) == 1);   /* map after a run */
	kgenome_emu_set_rip(e, 0x400000);
	kgenome_emu_set_reg(e, KGENOME_EMU_RCX, 0);
	kgenome_emu_set_max_insn(e, 100000);
	(void)kgenome_emu_run(e);                                /* run again from the top: answers, no fault */
	(void)kgenome_emu_run(e);
	(void)kgenome_emu_step(e);
	kgenome_emu_snap_written(e);
	kgenome_emu_free(e);

	CK(hk_isolated(borrowed_lifetime_case, NULL, 10, &sig) == HK_OK);   /* the bytes kgenome_emu_next_written hands out are freed by the next call, though emu.h says they stay valid until the emulator is freed */
	CK(hk_isolated(stale_walk_case, NULL, 10, &sig) == HK_OK);   /* kgenome_emu_next_written lists the pages written when it was FIRST called, whatever the run writes after */
}

/* ---- 3: NULL handles on the diagnose scan and the tables ------------------------------------------------- */

struct nt { const char *name; hk_case_fn fn; };

#define NT(name, expr) static int name(void *a) { \
	static struct hk_elf e; static struct kgenome_elf_info ei; struct kgenome_obj o; \
	struct kgenome_diag_scan *s; \
	(void)a; hk_elf(&e, 1, 0, 0); kgenome_elf_image_parse(kof_buf_make(e.b, e.n), &ei, &o); o.file_header = &ei; \
	s = kgenome_diag_scan(&o, e.b, e.n); (void)s; (void)(expr); return 0; }

NT(d_ran,      kgenome_diag_scan_ran(NULL))
NT(d_count,    kgenome_diag_scan_count(NULL))
NT(d_at,       kgenome_diag_scan_at(NULL, 0))
NT(d_str_at,   kgenome_diag_str_at(NULL, 0, 0))
NT(d_str_cnt,  kgenome_diag_str_count(NULL, 0))
NT(d_status,   kgenome_diag_scan_status(NULL))
NT(d_refused,  kgenome_diag_scan_refused(NULL))
NT(d_bytes,    kgenome_diag_scan_bytes(NULL, NULL))
NT(d_full,     kgenome_diag_scan_full(NULL))
NT(d_node,     kgenome_diag_str_at_node(NULL, 0, 0, "x"))
NT(d_apihash,  kgenome_diag_apihash(NULL, &o))
NT(d_with,     kgenome_diag_scan_with(NULL, e.b, e.n, KGENOME_DIAG_RUN_ALL))
NT(d_with_b,   kgenome_diag_scan_with(&o, NULL, e.n, KGENOME_DIAG_RUN_ALL))
NT(d_with_z,   kgenome_diag_scan_with(&o, e.b, 0, KGENOME_DIAG_RUN_ALL))
NT(d_funcs,    kgenome_diag_funcs_of(NULL, e.b, e.n, (struct kgenome_func_set *)&ei))
NT(d_code,     kgenome_diag_code_range(NULL, 0, 10, (uint64_t *)&ei))
NT(n_abi,      kgenome_nucleo_sys_name_abi(NULL, 1))
NT(n_abi2,     kgenome_nucleo_cap_of_syscall_abi(NULL, 1, NULL, NULL))
NT(l_cap_none, kgenome_nucleo_cap_of_name(NULL))

static const struct nt guarded[] = {
	{ "scan_with(NULL obj)", d_with }, { "scan_with(NULL bytes)", d_with_b }, { "scan_with(size 0)", d_with_z },
	{ "cap_of_name(NULL)", l_cap_none }, { "scan_ran", d_ran }, { "scan_count", d_count }, { "scan_at", d_at },
	{ "str_at", d_str_at }, { "str_count", d_str_cnt }, { "scan_status", d_status },
	{ "scan_refused", d_refused }, { "scan_bytes", d_bytes }, { "scan_full", d_full },
};
static const struct nt unguarded[] = {
	{ "str_at_node", d_node }, { "apihash", d_apihash },
	{ "diag_funcs_of(NULL obj)", d_funcs }, { "diag_code_range(NULL info)", d_code },
	{ "sys_name_abi(NULL abi)", n_abi }, { "cap_of_syscall_abi(NULL abi)", n_abi2 },
};

static void t_null_handles(void)
{
	char names[1024] = "";
	size_t at = 0;
	unsigned i, bad_n = 0;
	int sig = 0;

	for (i = 0; i < sizeof guarded / sizeof guarded[0]; i++)
		CK(hk_isolated(guarded[i].fn, NULL, 5, &sig) == HK_OK);
	for (i = 0; i < sizeof unguarded / sizeof unguarded[0]; i++) {
		if (hk_isolated(unguarded[i].fn, NULL, 5, &sig) != HK_OK) {
			bad_n++;
			at += (size_t)snprintf(names + at, sizeof names - at, "%s%s", at ? ", " : "", unguarded[i].name);
		}
	}
	if (bad_n)
		printf("  (crash on a NULL handle: %s)\n", names);
	CK(bad_n == 0);   /* 6 public diagnose and capability-table calls dereference a NULL handle their siblings accept */
}

/* ---- 4: threads --------------------------------------------------------------------------------------- */

#define NTHREADS 8

static pthread_barrier_t barrier;

/* a checksum over everything one thread's workload computes */
static uint64_t mix(uint64_t h, uint64_t v)
{
	h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
	return h;
}

static uint64_t workload(unsigned which)
{
	uint64_t h = 0x1234;
	struct hk_rng r = { 0xfeed0000ull + which };
	unsigned i, k;

	/* the decoders: the three lazily built tables and the x86 front end */
	for (i = 0; i < 40000; i++) {
		uint32_t w = (uint32_t)hk_next(&r);
		struct kgenome_arm32_insn a;
		struct kgenome_thumb_insn t;
		struct kgenome_arm64_insn b;
		uint8_t x[16];
		struct kgenome_x86_insn xi;

		(void)kgenome_arm32_decode(&a, w);
		h = mix(h, a.id);
		(void)kgenome_thumb_decode(&t, w >> 16, w & 0xffffu);
		h = mix(h, t.id);
		(void)kgenome_arm64_decode(&b, w);
		h = mix(h, b.id);
		for (k = 0; k < 16; k++)
			x[k] = (uint8_t)hk_next(&r);
		if (kgenome_x86_decode(&xi, x, 16, 64) == KGENOME_OK)
			h = mix(h, (uint64_t)xi.id << 8 | xi.len);
	}
	/* the emulator on its own programs */
	for (i = 0; i < 40; i++) {
		uint8_t code[128];
		struct kgenome_emu_cfg cfg = { 3000, 32, 0, 64 };
		struct kgenome_emu *e = kgenome_emu_new(&cfg);

		for (k = 0; k < sizeof code; k++)
			code[k] = (uint8_t)hk_next(&r);
		kgenome_emu_map(e, 0x400000, code, sizeof code, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
		kgenome_emu_map(e, 0x600000, NULL, 0, 0x4000, KGENOME_EMU_R | KGENOME_EMU_W);
		kgenome_emu_set_rip(e, 0x400000);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSP, 0x600000 + 0x2000);
		kgenome_emu_set_reg(e, KGENOME_EMU_RDI, 0x600000);
		h = mix(h, (uint64_t)kgenome_emu_run(e));
		h = mix(h, kgenome_emu_insn_count(e));
		for (k = 0; k < 16; k++)
			h = mix(h, kgenome_emu_get_reg(e, k));
		kgenome_emu_free(e);
	}
	/* the parsers, the walkers and a diagnose scan */
	for (i = 0; i < 4; i++) {
		static __thread struct hk_elf e;
		static __thread struct hk_pe pe;
		static __thread struct kgenome_elf_info ei;
		static __thread struct kgenome_pe_info pi;
		struct kgenome_obj o;
		struct kgenome_func_set fs;
		struct kgenome_diag_scan *s;

		hk_elf(&e, (int)(i & 1u), 0, (int)(i >> 1));
		kgenome_elf_image_parse(kof_buf_make(e.b, e.n), &ei, &o);
		o.file_header = &ei;
		kgenome_funcs_build(KGENOME_FMT_ELF, e.b, e.n, &ei, &fs);
		h = mix(h, fs.n);
		for (k = 0; k < fs.n; k++)
			h = mix(mix(h, fs.v[k].off), fs.v[k].len);
		kgenome_funcs_free(&fs);
		s = kgenome_diag_scan_with(&o, e.b, e.n, KGENOME_DIAG_RUN_ALL);
		if (s) {
			h = mix(h, kgenome_diag_scan_count(s));
			h = mix(h, kgenome_diag_scan_status(s));
			kgenome_diag_scan_free(s);
		}
		hk_pe(&pe, (int)(i & 1u));
		kgenome_pe_image_parse(kof_buf_make(pe.b, pe.n), &pi, &o);
		h = mix(h, pi.anomalies);
		{
			enum kgenome_status st;
			struct kgenome_pe_imptab t;
			h = mix(h, kgenome_pe_imports(kof_buf_make(pe.b, pe.n), &pi, NULL, NULL, &st));
			kgenome_pe_imptab_build(kof_buf_make(pe.b, pe.n), &pi, &t);
			h = mix(h, t.n);
			kgenome_pe_imptab_free(&t);
		}
	}
	/* the sweep, the map and the mutation windows */
	{
		struct kgenome_xref *u = kgenome_xref_new();
		struct kgenome_cell_state st;
		uint8_t buf[512];
		uint32_t np = 0, *pool;

		kgenome_xref_begin(u, KGENOME_ARCH_X86_64);
		kgenome_cell_state_reset(&st);
		for (i = 0; i < 20000; i++) {
			struct kgenome_cell_insn in;
			uint8_t b[16];
			for (k = 0; k < 16; k++)
				b[k] = (uint8_t)hk_next(&r);
			if (kgenome_cell_decode_x86(b, 16, 0x1000 + i, 64, &in)) {
				kgenome_xref_feed(u, &in);
				kgenome_cell_state_track(&st, &in);
			}
		}
		h = mix(h, kgenome_xref_in(u, 0x1000, 0x10000));
		h = mix(h, st.known);
		kgenome_xref_free(u);
		for (k = 0; k < sizeof buf; k++)
			buf[k] = (uint8_t)hk_next(&r);
		pool = kgenome_mutation_pool(buf, sizeof buf, KGENOME_MUTATION_RAW, &np);
		h = mix(h, np);
		for (k = 0; k < np; k += 16)
			h = mix(h, pool[k]);
		free(pool);
	}
	return h;
}

struct th { unsigned which; uint64_t result; };

static void *thread_main(void *arg)
{
	struct th *t = (struct th *)arg;

	pthread_barrier_wait(&barrier);               /* all eight start the cold tables together */
	t->result = workload(t->which);
	return NULL;
}

/* run in a fresh process: the ARM, Thumb and A64 tables have not been built yet */
static int fam_threads(void *arg)
{
	pthread_t th[NTHREADS];
	struct th res[NTHREADS];
	unsigned i, rounds;
	double t0 = hk_now();

	(void)arg;
	/* two kinds of thread: the same workload on all of them (the results must be identical), and
	 * a different one on each (so the shared tables see different words at once) */
	for (rounds = 0; rounds < 2; rounds++) {
		pthread_barrier_init(&barrier, NULL, NTHREADS);
		for (i = 0; i < NTHREADS; i++) {
			res[i].which = rounds ? i : 7;
			pthread_create(&th[i], NULL, thread_main, &res[i]);
		}
		for (i = 0; i < NTHREADS; i++)
			pthread_join(th[i], NULL);
		pthread_barrier_destroy(&barrier);
		for (i = 0; i < NTHREADS; i++) {
			uint64_t want = workload(rounds ? i : 7);       /* the single-threaded answer */
			if (res[i].result != want) {
				printf("  FAIL thread %u (workload %u): %#llx, single-threaded %#llx\n", i,
				       rounds ? i : 7u, (unsigned long long)res[i].result, (unsigned long long)want);
				hk_fails++;
			}
		}
	}
	return hk_fails != 0 || hk_now() - t0 > 30.0;
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);

	int sig = 0;
	enum hk_result r;

	if (hk_threads_only_v)                        /* for a ThreadSanitizer run: no forks, just the threads */
		return fam_threads(NULL);
	/* the threads go first, in a process whose lazy tables are cold: run in a child so the parent
	 * stays cold for nothing else, and so a crash is a result */
	r = hk_isolated(fam_threads, NULL, 120, &sig);
	printf("  parallel instances                         %s\n", r == HK_OK ? "ok" : r == HK_FAILED ? "FAILED" : r == HK_HUNG ? "HUNG" : "CRASHED");
	CK(r == HK_OK);
	t_free_rules();
	t_borrowed_buffers();
	t_null_handles();
	printf("hostile_lifetime: %d failure(s), %u known\n", hk_fails, km_known());
	return hk_fails != 0 || km_failed();
}
