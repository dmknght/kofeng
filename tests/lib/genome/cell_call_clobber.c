/*
 * cell_call_clobber - what a CALL does to the constant map (defect X1).
 *
 * The map was told nothing about a call except that it pushes a return address, so every constant a
 * callee may overwrite was still "known" afterwards. MEASURED on a hand-made program: `mov edx,7;
 * call g; ...; mov eax,10; syscall` with `g: xor edx,edx; ret` came out as mprotect(.., PROT_EXEC),
 * a capability the program does not have (a node that says memory is made executable).
 *
 * The rule (cell_state.c, kgenome_cell_call_keeps): a call that RETURNS leaves alone the registers the
 * architecture's calling convention makes the callee preserve, and every other register is unknown
 * afterwards. Not a call, because it fetches the program counter: `call next` and a callee that
 * begins by popping its own return address. The cursor knows the architecture; the map alone (no
 * cursor) keeps nothing across a call, the conservative default.
 *
 * Every case is a few instructions assembled by hand from the instruction set manuals, and each has a
 * CONTROL that must keep its value: a fix that forgets everything looks exactly like a fix that works
 * when only the clobbered register is checked.
 *
 * Why the old tests missed it: (a) no test tracked a CALL that was not `call next; pop` (api_celllysis
 * t_map_* never put a real call between a write and a read), and the map-versus-emulator differential
 * generates straight-line code with no call at all, so a wrong constant after a call had no oracle (c).
 */

#include <kgenome.h>

#include "hk.h"

#define VA 0x400000u

static int seg_at(void *priv, uint64_t off, struct kgenome_image_seg *out)
{
	(void)priv; (void)off;
	out->lo = 0;
	out->hi = 0x10000u;
	out->delta = (int64_t)VA;
	return 1;
}

static uint64_t off_of_va(void *priv, uint64_t va)
{
	(void)priv;
	return va >= VA && va < VA + 0x10000u ? va - VA : KGENOME_BROKEN;
}

struct code {
	uint8_t  b[256];
	unsigned n;
};

static void put(struct code *c, const uint8_t *p, unsigned n)
{
	memcpy(c->b + c->n, p, n);
	c->n += n;
}
#define PUT(c, ...) do { static const uint8_t b_[] = { __VA_ARGS__ }; put((c), b_, (unsigned)sizeof b_); } while (0)

/* Step `n` instructions from offset 0 and return the cursor, so the test reads the map afterwards. */
static void walk(unsigned arch, const struct code *c, unsigned n, struct kgenome_cell_cur *k)
{
	struct kgenome_cell_space sp;
	struct kgenome_cell_insn in;
	unsigned i;

	memset(&sp, 0, sizeof sp);
	memset(k, 0, sizeof *k);
	sp.base = c->b;
	sp.size = c->n;
	sp.arch = arch;
	sp.seg_at = seg_at;
	sp.off_of_va = off_of_va;
	CK(kgenome_cell_seek(k, 0, 0));
	for (i = 0; i < n; i++)
		CK(kgenome_cell_next(k, &sp, &in));
}

static int known(const struct kgenome_cell_cur *k, unsigned r, uint64_t want)
{
	uint64_t v = 0;

	return kgenome_cell_reg(k, (uint8_t)r, &v) && v == want;
}

static int unknown(const struct kgenome_cell_cur *k, unsigned r)
{
	uint64_t v;

	return !kgenome_cell_reg(k, (uint8_t)r, &v);
}

/* the registers by their decoder numbers */
enum { AX, CX, DX, BX, SP, BP, SI, DI };

static void t_x64(void)
{
	static struct code c;
	struct kgenome_cell_cur k;

	/* mov edx,7; mov ebx,3; mov r12d,9; mov esi,5; mov r8d,6; mov eax,1; call +0x20 */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);
	PUT(&c, 0xbb, 3, 0, 0, 0);
	PUT(&c, 0x41, 0xbc, 9, 0, 0, 0);
	PUT(&c, 0xbe, 5, 0, 0, 0);
	PUT(&c, 0x41, 0xb8, 6, 0, 0, 0);
	PUT(&c, 0xb8, 1, 0, 0, 0);
	PUT(&c, 0xe8, 0x20, 0, 0, 0);
	walk(KGENOME_ARCH_X86_64, &c, 6, &k);
	/* before the call everything is known: the control for the checks below */
	CK(known(&k, DX, 7) && known(&k, BX, 3) && known(&k, 12, 9) && known(&k, SI, 5) &&
	   known(&k, 8, 6) && known(&k, AX, 1));
	walk(KGENOME_ARCH_X86_64, &c, 7, &k);
	CK(unknown(&k, DX));            /* caller-saved: the callee may have written it */
	CK(unknown(&k, SI));
	CK(unknown(&k, 8));
	CK(unknown(&k, AX));            /* and rax is the return value */
	CK(known(&k, BX, 3));           /* callee-saved: the ABI makes the callee keep it */
	CK(known(&k, 12, 9));
}

static void t_x86(void)
{
	static struct code c;
	struct kgenome_cell_cur k;

	/* mov edx,7; mov ebx,3; mov esi,5; mov edi,6; mov ebp,8; call +0x20 */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);
	PUT(&c, 0xbb, 3, 0, 0, 0);
	PUT(&c, 0xbe, 5, 0, 0, 0);
	PUT(&c, 0xbf, 6, 0, 0, 0);
	PUT(&c, 0xbd, 8, 0, 0, 0);
	PUT(&c, 0xe8, 0x20, 0, 0, 0);
	walk(KGENOME_ARCH_X86, &c, 6, &k);
	CK(unknown(&k, DX));
	CK(known(&k, BX, 3));           /* cdecl, stdcall and fastcall all preserve these four */
	CK(known(&k, SI, 5));
	CK(known(&k, DI, 6));
	CK(known(&k, BP, 8));
}

static void t_not_a_call(void)
{
	static struct code c;
	struct kgenome_cell_cur k;
	struct kgenome_cell_space sp;
	struct kgenome_cell_insn in;

	/* `call next` is the address of the next instruction and nothing else: everything stays */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);
	PUT(&c, 0xb8, 1, 0, 0, 0);
	PUT(&c, 0xe8, 0, 0, 0, 0);
	walk(KGENOME_ARCH_X86_64, &c, 3, &k);
	CK(known(&k, DX, 7) && known(&k, AX, 1));

	/* the same through a callee that begins by popping its return address: `call L; db 'hi'; L: pop rsi` */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);              /* 0: mov edx,7 */
	PUT(&c, 0xb8, 1, 0, 0, 0);              /* 5: mov eax,1 */
	PUT(&c, 0xe8, 2, 0, 0, 0);              /* 10: call 17 */
	PUT(&c, 'h', 'i');                      /* 15: data */
	PUT(&c, 0x5e);                          /* 17: pop rsi */
	walk(KGENOME_ARCH_X86_64, &c, 3, &k);
	CK(known(&k, DX, 7) && known(&k, AX, 1));
	/* following the call: the pop takes the return address, which is the data's address */
	memset(&sp, 0, sizeof sp);
	sp.base = c.b; sp.size = c.n; sp.arch = KGENOME_ARCH_X86_64;
	sp.seg_at = seg_at; sp.off_of_va = off_of_va;
	CK(kgenome_cell_seek(&k, 17, 1));
	CK(kgenome_cell_next(&k, &sp, &in));
	CK(known(&k, SI, VA + 15u));

	/* a callee that does something else first is a call */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);
	PUT(&c, 0xe8, 2, 0, 0, 0);              /* 5: call 12 */
	PUT(&c, 'h', 'i');
	PUT(&c, 0x31, 0xd2);                    /* 12: xor edx,edx */
	walk(KGENOME_ARCH_X86_64, &c, 2, &k);
	CK(unknown(&k, DX));

	/* an indirect call: the callee is not known, so it is a call */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);
	PUT(&c, 0xff, 0xd0);                    /* call rax */
	walk(KGENOME_ARCH_X86_64, &c, 2, &k);
	CK(unknown(&k, DX));

	/* a jump is not a call */
	c.n = 0;
	PUT(&c, 0xba, 7, 0, 0, 0);
	PUT(&c, 0xeb, 0);                       /* jmp +0 */
	walk(KGENOME_ARCH_X86_64, &c, 2, &k);
	CK(known(&k, DX, 7));
}

/* The map with no cursor over it (a caller that decodes by itself) does not know the architecture,
 * so a call that returns keeps nothing, and `call next` still keeps everything. */
static void t_bare_map(void)
{
	struct kgenome_cell_state st;
	struct kgenome_cell_insn in;
	uint64_t v;
	static const uint8_t mov[] = { 0xba, 7, 0, 0, 0 }, call[] = { 0xe8, 0x20, 0, 0, 0 }, next[] = { 0xe8, 0, 0, 0, 0 };

	kgenome_cell_state_reset(&st);
	CK(kgenome_cell_decode_x86(mov, 5, 0x1000, 64, &in) == 5);
	kgenome_cell_state_track(&st, &in);
	CK(kgenome_cell_state_reg(&st, DX, &v) && v == 7);
	CK(kgenome_cell_decode_x86(next, 5, 0x1005, 64, &in) == 5);
	kgenome_cell_state_track(&st, &in);
	CK(kgenome_cell_state_reg(&st, DX, &v) && v == 7);
	CK(kgenome_cell_decode_x86(call, 5, 0x100a, 64, &in) == 5);
	kgenome_cell_state_track(&st, &in);
	CK(!kgenome_cell_state_reg(&st, DX, &v));
}

/* ARM: r0-r3 and r12 are the callee's, r4-r11 are kept. ARM64: every tracked register (x0-x15) is the callee's. */
static void t_arm(void)
{
	static struct code c;
	struct kgenome_cell_cur k;

	c.n = 0;
	PUT(&c, 0x07, 0x00, 0xa0, 0xe3);        /* mov r0,#7 */
	PUT(&c, 0x05, 0x40, 0xa0, 0xe3);        /* mov r4,#5 */
	PUT(&c, 0x09, 0xc0, 0xa0, 0xe3);        /* mov r12,#9 */
	PUT(&c, 0x00, 0x00, 0x00, 0xeb);        /* bl +8 (the callee starts two words on) */
	walk(KGENOME_ARCH_ARM, &c, 3, &k);
	CK(known(&k, 0, 7) && known(&k, 4, 5) && known(&k, 12, 9));
	walk(KGENOME_ARCH_ARM, &c, 4, &k);
	CK(unknown(&k, 0));
	CK(unknown(&k, 12));
	CK(known(&k, 4, 5));

	c.n = 0;
	PUT(&c, 0xe0, 0x00, 0x80, 0xd2);        /* mov x0,#7 */
	PUT(&c, 0xa9, 0x00, 0x80, 0xd2);        /* mov x9,#5 */
	PUT(&c, 0x02, 0x00, 0x00, 0x94);        /* bl +8 */
	walk(KGENOME_ARCH_ARM64, &c, 2, &k);
	CK(known(&k, 0, 7) && known(&k, 9, 5));
	walk(KGENOME_ARCH_ARM64, &c, 3, &k);
	CK(unknown(&k, 0));
	CK(unknown(&k, 9));
}

int main(int argc, char **argv)
{
	hk_args(argc, argv);
	t_x64();
	t_x86();
	t_not_a_call();
	t_bare_map();
	t_arm();
	printf("cell_call_clobber: %d failure(s)\n", hk_fails);
	return hk_fails != 0;
}
