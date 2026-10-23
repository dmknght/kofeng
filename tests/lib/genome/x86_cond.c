/*
 * x86_cond - kgenome_x86_cond_text and kgenome_x86_keeps_flags: what a conditional jump asks, in words.
 *
 * Every condition code (all sixteen) is read after each kind of flag setter the answer depends on - CMP of two registers, CMP against an immediate, TEST
 * of a register with itself, TEST of two registers - and after nothing known, and the text is compared with a table written here from the
 * architecture's definition of the codes, not from the library's: unsigned codes say (unsigned), signed ones (signed), equality neither, the sign
 * codes spell the difference, and the codes with no comparison in them fall back to the flag. Then what must NOT be said: a non-jump gets nothing, a
 * setter that is not CMP or TEST gets the flag text, a buffer one byte short gets nothing and is not overrun.
 */

#include <kgenome.h>
#include <genotype/x86/x86.h>

#include "hk.h"

/* CMP rax, rcx / CMP rdi, 3 / TEST rdi, rdi / TEST rax, rcx / ADD rax, rcx */
static const uint8_t cmp_rr[] = { 0x48, 0x39, 0xc8 };
static const uint8_t cmp_ri[] = { 0x48, 0x83, 0xff, 0x03 };
static const uint8_t test_rr[] = { 0x48, 0x85, 0xff };
static const uint8_t test_ab[] = { 0x48, 0x85, 0xc8 };
static const uint8_t add_rr[] = { 0x48, 0x01, 0xc8 };

static const char *const flags[16] = {
	"OF=1 (signed overflow)", "OF=0 (no signed overflow)",
	"CF=1 (unsigned below)", "CF=0 (unsigned above or equal)",
	"ZF=1 (equal / zero)", "ZF=0 (not equal / not zero)",
	"CF=1 or ZF=1 (unsigned below or equal)", "CF=0 and ZF=0 (unsigned above)",
	"SF=1 (negative)", "SF=0 (not negative)",
	"PF=1 (even parity)", "PF=0 (odd parity)",
	"SF!=OF (signed less)", "SF=OF (signed greater or equal)",
	"ZF=1 or SF!=OF (signed less or equal)", "ZF=0 and SF=OF (signed greater)"
};

/* the operator and signedness each comparison code means, from the definition of the codes */
static const char *const cmp_op[16] = { 0, 0, "<", ">=", "==", "!=", "<=", ">", 0, 0, 0, 0, "<", ">=", "<=", ">" };
static const char cmp_sg[16] = { 0, 0, 'u', 'u', 0, 0, 'u', 'u', 0, 0, 0, 0, 's', 's', 's', 's' };

static void dec(struct kgenome_x86_insn *i, const uint8_t *b, size_t n)
{
	CK(kgenome_x86_decode(i, b, n, 64) == KGENOME_OK);
}

static const char *jcc_text(unsigned cc, const struct kgenome_x86_insn *setter, char *buf, size_t cap)
{
	uint8_t j[2] = { (uint8_t)(0x70u + cc), 0x00 };
	struct kgenome_x86_insn ji;

	dec(&ji, j, sizeof j);
	CK(kgenome_x86_cond_text(&ji, setter, 0, buf, cap) > 0);
	return buf;
}

static void want(const char *got, const char *w, unsigned cc, const char *what)
{
	if (strcmp(got, w)) {
		printf("  cc %u after %s: got \"%s\", want \"%s\"\n", cc, what, got, w);
		hk_fails++;
	}
}

static void t_codes(void)
{
	struct kgenome_x86_insn rr, ri, tz, tab;
	unsigned cc;
	char got[256], w[256];

	dec(&rr, cmp_rr, sizeof cmp_rr);
	dec(&ri, cmp_ri, sizeof cmp_ri);
	dec(&tz, test_rr, sizeof test_rr);
	dec(&tab, test_ab, sizeof test_ab);
	for (cc = 0; cc < 16; cc++) {
		/* no setter known: the flag, whatever the code */
		want(jcc_text(cc, NULL, got, sizeof got), flags[cc], cc, "nothing known");
		/* CMP rax, rcx */
		if (cc == 8 || cc == 9)
			snprintf(w, sizeof w, "rax - rcx %s 0", cc == 8 ? "<" : ">=");
		else if (cmp_op[cc])
			snprintf(w, sizeof w, "rax %s rcx%s", cmp_op[cc], cmp_sg[cc] == 'u' ? " (unsigned)" : cmp_sg[cc] == 's' ? " (signed)" : "");
		else
			snprintf(w, sizeof w, "%s", flags[cc]);
		want(jcc_text(cc, &rr, got, sizeof got), w, cc, "cmp rax, rcx");
		/* CMP rdi, 3: an immediate is written short */
		if (cc == 8 || cc == 9)
			snprintf(w, sizeof w, "rdi - 0x3 %s 0", cc == 8 ? "<" : ">=");
		else if (cmp_op[cc])
			snprintf(w, sizeof w, "rdi %s 0x3%s", cmp_op[cc], cmp_sg[cc] == 'u' ? " (unsigned)" : cmp_sg[cc] == 's' ? " (signed)" : "");
		else
			snprintf(w, sizeof w, "%s", flags[cc]);
		want(jcc_text(cc, &ri, got, sizeof got), w, cc, "cmp rdi, 3");
		/* TEST rdi, rdi: a test of a value with itself is a test of the value; CF and OF are clear */
		{
			static const char *const op[16] = { 0, 0, 0, 0, "==", "!=", "==", "!=", "<", ">=", 0, 0, "<", ">=", "<=", ">" };

			if (cc == 2)
				snprintf(w, sizeof w, "never taken (test clears CF)");
			else if (cc == 3)
				snprintf(w, sizeof w, "always taken (test clears CF)");
			else if (op[cc])
				snprintf(w, sizeof w, "rdi %s 0", op[cc]);
			else
				snprintf(w, sizeof w, "%s", flags[cc]);
			want(jcc_text(cc, &tz, got, sizeof got), w, cc, "test rdi, rdi");
			if (cc == 2 || cc == 3)
				snprintf(w, sizeof w, cc == 2 ? "never taken (test clears CF)" : "always taken (test clears CF)");
			else if (op[cc])
				snprintf(w, sizeof w, "(rax & rcx) %s 0", op[cc]);
			else
				snprintf(w, sizeof w, "%s", flags[cc]);
			want(jcc_text(cc, &tab, got, sizeof got), w, cc, "test rax, rcx");
		}
	}
}

static void t_refusals(void)
{
	struct kgenome_x86_insn add, jmp, nop, j, rr;
	static const uint8_t jmp8[] = { 0xeb, 0x00 }, nop1[] = { 0x90 };
	char got[256], small[8];
	size_t n;

	dec(&add, add_rr, sizeof add_rr);
	dec(&jmp, jmp8, sizeof jmp8);
	dec(&nop, nop1, sizeof nop1);
	dec(&rr, cmp_rr, sizeof cmp_rr);
	/* after an ADD the flags are the add's, not a comparison's: the flag text only */
	want(jcc_text(4, &add, got, sizeof got), flags[4], 4, "add rax, rcx");
	/* not a conditional jump */
	memset(got, 'x', sizeof got);
	CK(kgenome_x86_cond_text(&jmp, &rr, 0, got, sizeof got) == 0 && got[0] == 0);
	CK(kgenome_x86_cond_text(&nop, NULL, 0, got, sizeof got) == 0);
	CK(kgenome_x86_cond_text(NULL, NULL, 0, got, sizeof got) == 0);
	/* a buffer too small gets nothing, never a cut word, and the byte after it is untouched */
	{
		uint8_t j2[2] = { 0x74, 0 };
		char guard[16];

		dec(&j, j2, sizeof j2);
		memset(guard, 0x5a, sizeof guard);
		n = kgenome_x86_cond_text(&j, NULL, 0, guard, 4);
		CK(n == 0 && guard[0] == 0 && guard[4] == 0x5a);
		/* exactly enough room for the text and its NUL, and one byte less: the first is written whole, the second not at all and nothing past it */
		{
			size_t len = strlen(flags[4]);
			char tight[64];

			memset(tight, 0x5a, sizeof tight);
			CK(kgenome_x86_cond_text(&j, NULL, 0, tight, len + 1u) == len && !strcmp(tight, flags[4]) && tight[len + 1u] == 0x5a);
			memset(tight, 0x5a, sizeof tight);
			CK(kgenome_x86_cond_text(&j, NULL, 0, tight, len) == 0 && tight[0] == 0 && tight[len] == 0x5a);
		}
		n = kgenome_x86_cond_text(&j, NULL, 0, small, sizeof small);
		CK(n == 0 && small[0] == 0);
		CK(kgenome_x86_cond_text(&j, NULL, 0, small, 0) == 0);
	}
}

static void t_cmp_text(void)
{
	struct kgenome_x86_insn rr, ri, tz, tab, add;
	char got[128];
	size_t n;

	dec(&rr, cmp_rr, sizeof cmp_rr);
	dec(&ri, cmp_ri, sizeof cmp_ri);
	dec(&tz, test_rr, sizeof test_rr);
	dec(&tab, test_ab, sizeof test_ab);
	dec(&add, add_rr, sizeof add_rr);
	CK(kgenome_x86_cmp_text(&rr, 0, got, sizeof got) > 0 && !strcmp(got, "compare rax with rcx"));
	CK(kgenome_x86_cmp_text(&ri, 0, got, sizeof got) > 0 && !strcmp(got, "compare rdi with 0x3"));
	CK(kgenome_x86_cmp_text(&tz, 0, got, sizeof got) > 0 && !strcmp(got, "compare rdi with 0"));
	CK(kgenome_x86_cmp_text(&tab, 0, got, sizeof got) > 0 && !strcmp(got, "test rax & rcx"));
	/* neither a CMP nor a TEST: nothing, and the buffer is empty */
	memset(got, 'x', sizeof got);
	CK(kgenome_x86_cmp_text(&add, 0, got, sizeof got) == 0 && got[0] == 0);
	CK(kgenome_x86_cmp_text(NULL, 0, got, sizeof got) == 0);
	/* exactly enough room for the text and its NUL, then one byte less: whole, or nothing and nothing written past it */
	n = strlen("compare rax with rcx");
	memset(got, 0x5a, sizeof got);
	CK(kgenome_x86_cmp_text(&rr, 0, got, n + 1u) == n && got[n + 1u] == 0x5a);
	memset(got, 0x5a, sizeof got);
	CK(kgenome_x86_cmp_text(&rr, 0, got, n) == 0 && got[0] == 0 && got[n] == 0x5a);
}

static void t_keeps_flags(void)
{
	struct kgenome_x86_insn i;
	static const struct { uint8_t b[4]; unsigned n; int keeps; } t[] = {
		{ { 0x48, 0x89, 0xc8 }, 3, 1 },        /* mov rax, rcx */
		{ { 0x48, 0x8d, 0x07 }, 3, 1 },        /* lea rax, [rdi] */
		{ { 0x90 }, 1, 1 },                    /* nop */
		{ { 0x50 }, 1, 1 },                    /* push rax */
		{ { 0x58 }, 1, 1 },                    /* pop rax */
		{ { 0x0f, 0xb6, 0xc1 }, 3, 1 },        /* movzx eax, cl */
		{ { 0x74, 0x00 }, 2, 1 },              /* je */
		{ { 0x48, 0x01, 0xc8 }, 3, 0 },        /* add rax, rcx */
		{ { 0x48, 0x39, 0xc8 }, 3, 0 },        /* cmp */
		{ { 0x48, 0x85, 0xc0 }, 3, 0 },        /* test */
		{ { 0x48, 0xff, 0xc0 }, 3, 0 },        /* inc rax */
		{ { 0x48, 0xd1, 0xe0 }, 3, 0 },        /* shl rax, 1 */
		{ { 0x48, 0x31, 0xc0 }, 3, 0 },        /* xor rax, rax */
		{ { 0xe8, 0, 0, 0 }, 4, 0 },           /* call: the callee changes them */
	};
	unsigned k;

	for (k = 0; k < sizeof t / sizeof t[0]; k++) {
		uint8_t b[16] = { 0 };

		memcpy(b, t[k].b, t[k].n);
		if (t[k].b[0] == 0xe8)
			b[4] = b[3] = 0;
		CK(kgenome_x86_decode(&i, b, sizeof b, 64) == KGENOME_OK);
		if (kgenome_x86_keeps_flags(&i) != t[k].keeps) {
			printf("  case %u: keeps_flags = %d, want %d\n", k, kgenome_x86_keeps_flags(&i), t[k].keeps);
			hk_fails++;
		}
	}
}

static void t_shorten(void)
{
	char a[] = "MOV rax, 0x0000000000000022", b[] = "ADD rax, 0x0000000000000000 ; 0xff 0x0a x0", c[] = "no hex here";

	kgenome_x86_shorten(a);
	kgenome_x86_shorten(b);
	kgenome_x86_shorten(c);
	CK(!strcmp(a, "MOV rax, 0x22"));
	CK(!strcmp(b, "ADD rax, 0x0 ; 0xff 0xa x0"));
	CK(!strcmp(c, "no hex here"));
}

int main(void)
{
	t_codes();
	t_refusals();
	t_cmp_text();
	t_keeps_flags();
	t_shorten();
	if (hk_fails) {
		printf("x86_cond: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("x86_cond: ok\n");
	return 0;
}
