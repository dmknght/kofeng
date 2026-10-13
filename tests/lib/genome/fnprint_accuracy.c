/*
 * fnprint_accuracy - the fingerprint says what it is meant to say.
 *
 * Equal where the function is the same function (moved, relocated, padded, its
 * operand fields that the normal form drops changed); different where it is
 * a different function or where a field that carries meaning changed. And the
 * relevance decision says AUTHOR / LIB / UNKNOWN for the reasons it reports.
 */
#include "fnprint_kit.h"
#include "../../unit/known_miss.h"

static struct fk_var V0 = { 0x1000, 0x2000, 0x12345678u };

static uint64_t one_fp(const struct fk_obj *o, uint32_t i, uint64_t *fw)
{
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	uint64_t fp;

	fk_req(&rq, o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	kgenome_fnprint_collect(&rq, &s);
	fp = i < s.n ? s.fn[i].fp : 0;
	if (fw)
		*fw = i < s.n ? s.fn[i].fw : 0;
	kgenome_fnprint_set_free(&s, NULL);
	return fp;
}

static void t_moved_and_relocated(void)
{
	struct fk_obj a, b;
	struct fk_var v1 = { -0x7700, 0x40404, 0x7eadbeefu };
	uint64_t fa, fb, wa, wb;

	fk_init(&a); fk_init(&b);
	fk_func(&a, 7, 40, &V0);
	fk_fill(&b, 0x90, 4096);                 /* the same function 4 KiB further */
	fk_func(&b, 7, 40, &v1);                 /* ...with another call/rip/imm field */
	fa = one_fp(&a, 0, &wa);
	fb = one_fp(&b, 0, &wb);
	CK(fa && fa == fb);
	CK(wa == wb);
	fk_free(&a); fk_free(&b);
}

static void t_different_functions_differ(void)
{
	struct fk_obj a;
	uint32_t i, j;
	uint64_t fp[32];

	fk_init(&a);
	for (i = 0; i < 32; i++)
		fk_func(&a, 100 + i, 30, &V0);
	for (i = 0; i < 32; i++)
		fp[i] = one_fp(&a, i, NULL);
	for (i = 0; i < 32; i++)
		for (j = i + 1; j < 32; j++)
			CK(fp[i] != fp[j]);
	fk_free(&a);
}

/* A change a normal form must see: one opcode, one small immediate, one register. */
static void t_semantic_change_differs(void)
{
	struct fk_obj a, b;
	uint8_t code[512];
	uint32_t n, k;
	uint64_t base;

	fk_init(&a);
	n = fk_code(code, 11, 40, &V0);
	fk_raw(&a, code, n); fk_mark(&a, 0, n);
	base = one_fp(&a, 0, NULL);
	for (k = 4; k + 2 < n; k++) {
		/* flip the first byte of the first `xor eax,eax` into `or eax,eax` (31 -> 09) */
		if (code[k] == 0x31 && code[k + 1] == 0xc0) {
			uint8_t c2[512];

			memcpy(c2, code, n);
			c2[k] = 0x09;
			fk_init(&b);
			fk_raw(&b, c2, n); fk_mark(&b, 0, n);
			CK(one_fp(&b, 0, NULL) != base);
			fk_free(&b);
			break;
		}
	}
	/* the small immediate of `add eax, imm8` changed 1 -> 2 */
	for (k = 4; k + 2 < n; k++)
		if (code[k] == 0x83 && code[k + 1] == 0xc0 && code[k + 2] != 0x01) {
			uint8_t c2[512];

			memcpy(c2, code, n);
			c2[k + 2] ^= 0x04;
			fk_init(&b);
			fk_raw(&b, c2, n); fk_mark(&b, 0, n);
			CK(one_fp(&b, 0, NULL) != base);
			fk_free(&b);
			break;
		}
	fk_free(&a);
}

/* A register swap changes `fp` and leaves the weak fingerprint alone. */
static void t_register_swap_weak(void)
{
	/* mov eax,5 ; add eax,1 ; ret   versus   mov ecx,5 ; add ecx,1 ; ret */
	static const uint8_t x[] = { 0xb8, 5, 0, 0, 0, 0x83, 0xc0, 1, 0xc3 };
	static const uint8_t y[] = { 0xb9, 5, 0, 0, 0, 0x83, 0xc1, 1, 0xc3 };
	struct fk_obj a, b;
	uint64_t wa, wb;

	fk_init(&a); fk_init(&b);
	fk_raw(&a, x, sizeof x); fk_mark(&a, 0, sizeof x);
	fk_raw(&b, y, sizeof y); fk_mark(&b, 0, sizeof y);
	CK(one_fp(&a, 0, &wa) != one_fp(&b, 0, &wb));
	CK(wa == wb);
	fk_free(&a); fk_free(&b);
}

/* Trailing alignment (nop, int3, zero bytes) is not part of the function; a nop inside is not either. */
static void t_padding_is_not_content(void)
{
	struct fk_obj a, b;
	uint8_t code[512];
	uint32_t n = fk_code(code, 3, 25, &V0);
	uint64_t fa, fb;

	fk_init(&a); fk_init(&b);
	fk_raw(&a, code, n); fk_mark(&a, 0, n);
	fk_raw(&b, code, n);
	/* int3, nop, and the multi-byte nop (nopl 0(%rax,%rax,1)) a linker aligns with */
	fk_fill(&b, 0xcc, 5); fk_fill(&b, 0x90, 3);
	fk_raw(&b, "\x0f\x1f\x44\x00\x00", 5);
	fk_mark(&b, 0, b.n);                     /* the extent includes the padding */
	fa = one_fp(&a, 0, NULL);
	fb = one_fp(&b, 0, NULL);
	CK(fa == fb);
	fk_free(&a); fk_free(&b);
}

/* The branch that stays inside the function is a position in it; moving the call target does not matter. */
static void t_internal_branch_is_kept(void)
{
	static const uint8_t x[] = { 0x31, 0xc0, 0x74, 0x02, 0xff, 0xc0, 0xc3 };   /* je +2 */
	static const uint8_t y[] = { 0x31, 0xc0, 0x74, 0x01, 0xff, 0xc0, 0xc3 };   /* je +1 */
	struct fk_obj a, b;

	fk_init(&a); fk_init(&b);
	fk_raw(&a, x, sizeof x); fk_mark(&a, 0, sizeof x);
	fk_raw(&b, y, sizeof y); fk_mark(&b, 0, sizeof y);
	CK(one_fp(&a, 0, NULL) != one_fp(&b, 0, NULL));
	fk_free(&a); fk_free(&b);
}

/* The reasons a static function is the author's or the library's: main, reached from main, a wrapper, beyond the frontier. */
static void t_static_relevance(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;
	uint64_t main_off, e, site[2], a1, a2;
	uint32_t i;

	fk_init(&o);
	/* entry, main (calls the two author functions), the author functions, then the library: three wrappers and more */
	e = fk_entry(&o, 0);                         /* patched below */
	main_off = fk_stub(&o, 2, site);
	a1 = fk_func(&o, 1, 40, &V0);
	a2 = fk_func(&o, 2, 40, &V0);
	fk_call_to(&o, site[0], a1);
	fk_call_to(&o, site[1], a2);
	fk_wrapper(&o, 1); fk_wrapper(&o, 2); fk_wrapper(&o, 3);
	fk_func(&o, 50, 40, &V0);                    /* a function after the frontier */
	{
		int32_t d = (int32_t)((int64_t)main_off - (int64_t)(e + 7));

		memcpy(o.b + e + 3, &d, 4);
	}
	fk_req(&rq, &o, KGENOME_FNP_LINK_STATIC, &st, &fs);
	rq.entry_off = e;
	kgenome_fnprint_collect(&rq, &s);
	CK(s.n == 8);
	CK(s.stat.main_off == main_off && st.main_off == main_off);
	CK(s.fn[0].cls == KGENOME_FNP_LIB && (s.fn[0].reason & KGENOME_FNP_R_STARTUP));
	CK(s.fn[1].cls == KGENOME_FNP_AUTHOR && (s.fn[1].reason & KGENOME_FNP_R_MAIN));
	CK(s.fn[2].cls == KGENOME_FNP_AUTHOR && (s.fn[2].reason & KGENOME_FNP_R_REACHED));
	CK(s.fn[3].cls == KGENOME_FNP_AUTHOR && (s.fn[3].reason & KGENOME_FNP_R_REACHED));
	for (i = 4; i < 7; i++)
		CK(s.fn[i].cls == KGENOME_FNP_LIB && (s.fn[i].reason & KGENOME_FNP_R_WRAPPER));
	CK(s.fn[7].cls == KGENOME_FNP_LIB && (s.fn[7].reason & KGENOME_FNP_R_BEYOND));
	CK(s.stat.frontier_off == s.fn[6].off);
	CK(s.stat.n_reached == 2 && s.stat.n_region_over == 0);
	CK(s.stat.status == KGENOME_OK);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* A dynamic object: every function with a body is the author's, and says why. */
static void t_dynamic_relevance(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;

	fk_init(&o);
	fk_func(&o, 1, 40, &V0);
	fk_func(&o, 2, 40, &V0);
	fk_req(&rq, &o, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	kgenome_fnprint_collect(&rq, &s);
	CK(s.n == 2 && s.fn[0].cls == KGENOME_FNP_AUTHOR && (s.fn[0].reason & KGENOME_FNP_R_DYNAMIC));
	CK(s.fn[0].weight > 0);
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

/* Not told how the object is linked: nothing is called the author's without evidence. */
static void t_unknown_link_is_unknown(void)
{
	struct fk_obj o;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s;

	fk_init(&o);
	fk_func(&o, 1, 40, &V0);
	fk_req(&rq, &o, KGENOME_FNP_LINK_UNKNOWN, &st, &fs);
	kgenome_fnprint_collect(&rq, &s);
	CK(s.n == 1 && s.fn[0].cls == KGENOME_FNP_UNKNOWN && (s.fn[0].reason & KGENOME_FNP_R_NO_FRONTIER));
	CK(s.fn[0].weight > 0 && s.fn[0].weight < 40);      /* weighted at the UNKNOWN share */
	kgenome_fnprint_set_free(&s, NULL);
	fk_free(&o);
}

static uint64_t tag_of_target(void *user, uint64_t to)
{
	(void)user;
	return to;
}

/* The hook that names where a call leaves to (an import's name): the same body calling another import is another function; without it, equal. */
static void t_ext_hook(void)
{
	/* push rbp; mov rbp,rsp; call rel32; pop rbp; ret - and the same with another target */
	uint8_t x[] = { 0x55, 0x48, 0x89, 0xe5, 0xe8, 0, 0, 0, 0, 0x5d, 0xc3 };
	struct fk_obj a, b;
	struct kgenome_fnprint_req rq;
	struct kgenome_fnprint_stat st;
	struct kgenome_func_set fs;
	struct kgenome_fnprint_set s1, s2, s3, s4;
	int32_t d1 = 0x1000, d2 = 0x2000;

	fk_init(&a); fk_init(&b);
	memcpy(x + 5, &d1, 4);
	fk_raw(&a, x, sizeof x); fk_mark(&a, 0, sizeof x);
	memcpy(x + 5, &d2, 4);
	fk_raw(&b, x, sizeof x); fk_mark(&b, 0, sizeof x);
	fk_req(&rq, &a, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.opt.tiny_insn = 2;
	kgenome_fnprint_collect(&rq, &s1);
	fk_req(&rq, &b, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.opt.tiny_insn = 2;
	kgenome_fnprint_collect(&rq, &s2);
	CK(s1.fn[0].fp == s2.fn[0].fp);                        /* a class: where it leaves to is not in the fingerprint */
	fk_req(&rq, &a, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.hint.ext = tag_of_target;
	kgenome_fnprint_collect(&rq, &s3);
	fk_req(&rq, &b, KGENOME_FNP_LINK_DYNAMIC, &st, &fs);
	rq.hint.ext = tag_of_target;
	kgenome_fnprint_collect(&rq, &s4);
	CK(s3.fn[0].fp != s4.fn[0].fp);                        /* named by the caller's hook: two imports, two functions */
	CK(s3.fn[0].fw == s4.fn[0].fw);
	kgenome_fnprint_set_free(&s1, NULL); kgenome_fnprint_set_free(&s2, NULL);
	kgenome_fnprint_set_free(&s3, NULL); kgenome_fnprint_set_free(&s4, NULL);
	fk_free(&a); fk_free(&b);
}

int main(void)
{
	t_moved_and_relocated();
	t_different_functions_differ();
	t_semantic_change_differs();
	t_register_swap_weak();
	t_padding_is_not_content();
	t_internal_branch_is_kept();
	t_static_relevance();
	t_dynamic_relevance();
	t_unknown_link_is_unknown();
	t_ext_hook();
	printf("fnprint_accuracy: %s\n", hk_fails ? "FAIL" : "ok");
	return hk_fails != 0 || km_failed();
}
