/*
 * api_codemap - kgenome_codemap against a MODEL OF IT written the other way round.
 *
 * The generator lays out random x86-64 code from templates whose bytes and lengths are known, so it knows, without decoding anything, where each
 * branch is, where it goes, which way, and what the number register holds at each syscall: the model drops what it knows after every branch and at
 * every place a branch lands, exactly the rule the lib states. The table the lib builds from the BYTES is compared with it, entry for entry, over
 * thousands of random layouts. Targets are chosen to cover the edges: before the first byte, past the last, in the middle of an instruction, onto the
 * branch itself, forward and backward, rel8 at both ends of its range.
 *
 * Then the questions the table answers (the reference at an offset, who refers to a place) are asked of every offset and compared with a
 * brute-force count, and the relocation flag is checked against a table written by hand.
 */

#include <kgenome.h>
#include <phenotype/codemap.h>

#include "hk.h"

enum { T_NOP, T_MOV_EAX, T_XOR_EAX, T_LOAD_EAX, T_MOV_EBX, T_JMP8, T_JMP32, T_JCC8, T_JCC32, T_CALL, T_RET, T_LOOP,
       T_JMPR, T_CALLR, T_SYSCALL, T_INT80, T_N };

struct ins {
	uint8_t  kind;
	uint8_t  len;
	uint32_t at;
	int64_t  to;            /* branch: the target offset the generator chose, any value */
	uint32_t imm;
};

static const uint8_t g_len[T_N] = { 1, 5, 2, 2, 5, 2, 5, 2, 6, 5, 1, 2, 2, 2, 2, 2 };

static int is_direct(unsigned k)
{
	return k == T_JMP8 || k == T_JMP32 || k == T_JCC8 || k == T_JCC32 || k == T_CALL || k == T_LOOP;
}

static int ends_line(unsigned k)
{
	return is_direct(k) || k == T_RET || k == T_JMPR || k == T_CALLR;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* One layout: n instructions, their bytes in `buf`, returns the size. */
static uint32_t layout(struct hk_rng *r, struct ins *in, unsigned n, uint8_t *buf)
{
	uint32_t at = 0, size;
	unsigned i;

	for (i = 0; i < n; i++) {
		in[i].kind = (uint8_t)(hk_next(r) % T_N);
		in[i].len = g_len[in[i].kind];
		in[i].at = at;
		in[i].imm = (uint32_t)(hk_next(r) % 0x200u);
		at += in[i].len;
	}
	size = at;
	for (i = 0; i < n; i++) {
		uint32_t next = in[i].at + in[i].len;
		uint8_t *p = buf + in[i].at;
		unsigned k = in[i].kind;

		if (is_direct(k)) {
			unsigned how = (unsigned)(hk_next(r) % 10u);
			int64_t t;

			if (k == T_JMP8 || k == T_JCC8 || k == T_LOOP)
				t = (int64_t)next + (int64_t)(hk_next(r) % 256u) - 128;     /* both ends of rel8 */
			else if (how < 6)
				t = in[hk_next(r) % n].at;                                    /* an instruction start */
			else if (how < 7)
				t = (int64_t)size + (int64_t)(hk_next(r) % 40u);              /* past the end */
			else if (how < 8)
				t = -(int64_t)(hk_next(r) % 40u) - 1;                          /* before the start */
			else if (how < 9)
				t = in[i].at;                                                 /* onto itself */
			else
				t = (int64_t)(hk_next(r) % size);                            /* anywhere: maybe mid-instruction */
			in[i].to = t;
			if (k == T_JMP8) { p[0] = 0xeb; p[1] = (uint8_t)(int8_t)(t - next); }
			else if (k == T_JCC8) { p[0] = 0x74; p[1] = (uint8_t)(int8_t)(t - next); }
			else if (k == T_LOOP) { p[0] = 0xe2; p[1] = (uint8_t)(int8_t)(t - next); }
			else if (k == T_JMP32) { p[0] = 0xe9; put32(p + 1, (uint32_t)(t - next)); }
			else if (k == T_JCC32) { p[0] = 0x0f; p[1] = 0x84; put32(p + 2, (uint32_t)(t - next)); }
			else { p[0] = 0xe8; put32(p + 1, (uint32_t)(t - next)); }
			continue;
		}
		switch (k) {
		case T_NOP:     p[0] = 0x90; break;
		case T_MOV_EAX: p[0] = 0xb8; put32(p + 1, in[i].imm); break;
		case T_XOR_EAX: p[0] = 0x31; p[1] = 0xc0; break;
		case T_LOAD_EAX: p[0] = 0x8b; p[1] = 0x07; break;
		case T_MOV_EBX: p[0] = 0xbb; put32(p + 1, in[i].imm); break;
		case T_RET:     p[0] = 0xc3; break;
		case T_JMPR:    p[0] = 0xff; p[1] = 0xe0; break;
		case T_CALLR:   p[0] = 0xff; p[1] = 0xd0; break;
		case T_SYSCALL: p[0] = 0x0f; p[1] = 0x05; break;
		default:        p[0] = 0xcd; p[1] = 0x80; break;
		}
	}
	return size;
}

/* the in-object target of instruction i, or -1 */
static int64_t tgt_of(const struct ins *in, unsigned i, uint32_t size)
{
	return is_direct(in[i].kind) && in[i].to >= 0 && in[i].to < (int64_t)size ? in[i].to : -1;
}

static int is_start(const struct ins *in, unsigned n, int64_t off)
{
	unsigned i;

	for (i = 0; i < n; i++)
		if ((int64_t)in[i].at == off)
			return 1;
	return 0;
}

static unsigned expect_kind(unsigned k)
{
	switch (k) {
	case T_JMP8: case T_JMP32: case T_JMPR: return KGENOME_CM_JMP;
	case T_JCC8: case T_JCC32: return KGENOME_CM_JCC;
	case T_LOOP: return KGENOME_CM_LOOP;
	case T_CALL: case T_CALLR: return KGENOME_CM_CALL;
	case T_RET: return KGENOME_CM_RET;
	default: return KGENOME_CM_SYSCALL;
	}
}

static int is_ref(unsigned k)
{
	return k >= T_JMP8 && k != T_MOV_EBX && k != T_LOAD_EAX && k != T_XOR_EAX && k != T_MOV_EAX && k != T_NOP;
}

/* The model, run over the generated instructions: what the table must say. */
static void check_layout(const struct ins *in, unsigned n, uint32_t size, const uint8_t *buf)
{
	struct kgenome_obj obj = { .format = KGENOME_FMT_NONE, .arch = KGENOME_ARCH_X86_64, .obj_size = size };
	struct kgenome_codemap m;
	int64_t eax = -1;
	unsigned i, ri = 0, probe;

	CK(kgenome_codemap_build(&obj, buf, size, NULL, &m) == 1);
	for (i = 0; i < n; i++) {
		unsigned k = in[i].kind, hit;
		int64_t t;

		/* a place a branch lands drops what was known */
		for (probe = 0, hit = 0; probe < n && !hit; probe++)
			hit = tgt_of(in, probe, size) == (int64_t)in[i].at;
		if (i == 0 || hit)
			eax = -1;
		if (k == T_MOV_EAX)
			eax = in[i].imm;
		else if (k == T_XOR_EAX)
			eax = 0;
		else if (k == T_LOAD_EAX)
			eax = -1;
		if (!is_ref(k)) {
			CK(kgenome_codemap_at(&m, in[i].at) == NULL);
			continue;
		}
		CK(ri < m.n);
		if (ri < m.n) {
			const struct kgenome_codemap_ref *r = &m.v[ri];

			CK(r->at == in[i].at && r->len == in[i].len && r->kind == expect_kind(k));
			t = tgt_of(in, i, size);
			CK((t < 0 ? r->to == KGENOME_BROKEN : (int64_t)r->to == t));
			CK(!!(r->flags & KGENOME_CMF_INDIRECT) == (k == T_JMPR || k == T_CALLR));
			CK(!!(r->flags & KGENOME_CMF_BACK) == (t >= 0 && t <= (int64_t)in[i].at));
			CK(!!(r->flags & KGENOME_CMF_INT80) == (k == T_INT80));
			CK(!!(r->flags & KGENOME_CMF_NR) == ((k == T_SYSCALL || k == T_INT80) && eax >= 0));
			if (r->flags & KGENOME_CMF_NR)
				CK((int64_t)r->nr == eax);
			CK(kgenome_codemap_at(&m, in[i].at) == r);
		}
		ri++;
		if (ends_line(k) || k == T_SYSCALL || k == T_INT80)
			eax = -1;
	}
	CK(ri == m.n);

	/* who refers to a place: every offset, against a brute-force count */
	for (probe = 0; probe < size; probe++) {
		uint32_t first, want = 0, got = kgenome_codemap_to(&m, probe, &first), j;

		for (i = 0; i < n; i++)
			want += tgt_of(in, i, size) == (int64_t)probe;
		CK(got == want);
		for (j = 0; j < got; j++)
			CK(m.v[m.by_to[first + j]].to == probe);
		if (!is_start(in, n, probe))
			CK(kgenome_codemap_at(&m, probe) == NULL);
	}
	kgenome_codemap_free(&m);
}

static void t_random_layouts(void)
{
	struct hk_rng r = { 0x9e3779b97f4a7c15ull };
	unsigned round;

	for (round = 0; round < 3000; round++) {
		struct ins in[64];
		uint8_t buf[64 * 6 + 8];
		unsigned n = 1u + (unsigned)(hk_next(&r) % 60u);
		uint32_t size = layout(&r, in, n, buf);

		check_layout(in, n, size, buf);
	}
}

/* The edges that a random layout reaches only rarely, named. */
static void t_named_edges(void)
{
	struct kgenome_obj obj = { .format = KGENOME_FMT_NONE, .arch = KGENOME_ARCH_X86_64 };
	struct kgenome_codemap m;
	static const uint8_t jmp_self[] = { 0xeb, 0xfe };                       /* jmp $ */
	static const uint8_t two[] = { 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05 };       /* mov eax,60; syscall */
	static const uint8_t join[] = { 0xb8, 0x3c, 0, 0, 0, 0xeb, 0x00, 0x0f, 0x05 }; /* the jmp lands on the syscall: a join */
	uint32_t first;

	obj.obj_size = sizeof jmp_self;
	CK(kgenome_codemap_build(&obj, jmp_self, sizeof jmp_self, NULL, &m) == 1);
	CK(m.n == 1 && m.v[0].to == 0 && (m.v[0].flags & KGENOME_CMF_BACK));
	CK(kgenome_codemap_to(&m, 0, &first) == 1);
	kgenome_codemap_free(&m);

	obj.obj_size = sizeof two;
	CK(kgenome_codemap_build(&obj, two, sizeof two, NULL, &m) == 1);
	CK(m.n == 1 && m.v[0].kind == KGENOME_CM_SYSCALL && (m.v[0].flags & KGENOME_CMF_NR) && m.v[0].nr == 60u);
	kgenome_codemap_free(&m);

	obj.obj_size = sizeof join;
	CK(kgenome_codemap_build(&obj, join, sizeof join, NULL, &m) == 1);
	CK(m.n == 2 && m.v[1].kind == KGENOME_CM_SYSCALL && !(m.v[1].flags & KGENOME_CMF_NR));
	kgenome_codemap_free(&m);

	/* nothing to read, and an architecture with no decoder, are answers and not crashes */
	CK(kgenome_codemap_build(&obj, join, 0, NULL, &m) == 0 && m.n == 0);
	kgenome_codemap_free(&m);
}

/* A call whose displacement a relocation patches names no target. */
static void t_relocated_call(void)
{
	struct kgenome_obj obj = { .format = KGENOME_FMT_NONE, .arch = KGENOME_ARCH_X86_64, .obj_size = 6 };
	static const uint8_t code[] = { 0xe8, 0, 0, 0, 0, 0xc3 };
	struct kgenome_elf_reloc rel = { .where = 1, .nameoff = 1, .code = 1, .call = 1 };
	struct kgenome_elf_relocs t = { .v = &rel, .n = 1 };
	struct kgenome_codemap m;

	CK(kgenome_codemap_build(&obj, code, sizeof code, &t, &m) == 1);
	CK(m.n == 2 && m.v[0].kind == KGENOME_CM_CALL && (m.v[0].flags & KGENOME_CMF_RELOC) && m.v[0].to == KGENOME_BROKEN);
	CK(m.n_to == 0);
	kgenome_codemap_free(&m);
	CK(kgenome_codemap_build(&obj, code, sizeof code, NULL, &m) == 1);
	CK(m.v[0].to == 5 && !(m.v[0].flags & KGENOME_CMF_RELOC));     /* without the table it is call-next */
	kgenome_codemap_free(&m);
}

int main(void)
{
	t_random_layouts();
	t_named_edges();
	t_relocated_call();
	if (hk_fails) {
		printf("api_codemap: %d failure(s)\n", hk_fails);
		return 1;
	}
	printf("api_codemap: ok\n");
	return 0;
}
