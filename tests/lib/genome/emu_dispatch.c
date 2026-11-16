/*
 * emu_dispatch.c - THE EMULATOR'S DISPATCH TABLE (struct kgenome_emu_arch), against the lib alone.
 *
 * The emulator is one core and one entry per architecture; x86 and x86-64 are the first entry. What is
 * checked here is what the core takes from the entry and nothing else: the entry a machine is made with
 * (every width, a fork), the register roles a loader and the null-call gate read (the stack pointer, the
 * answer register, the seed registers), the system call conventions the Linux environment reads through
 * (number, arguments, the guest word and the numbering), and the run's one pointer.
 *
 * Two defects found while moving those reads into the table are pinned here, each RED on the code before
 * the change:
 *   ED1  `int 0x80` from 64-bit code read edx as the whole of rdx where the convention (and the kernel)
 *        takes 32 bits: pwrite64 answered 0x100000007 for a count of 7 with a stale upper half.
 *   ED2  the ELF loader built a 32-bit guest's initial stack out of 8-byte words: argc was followed by a
 *        zero where argv[0] belongs, and every auxv pair sat at twice its offset.
 *   ED3  `pop` into a segment register was answered as a guest FAULT with no fault recorded, so the run
 *        ended as "access at 0x0"; the register is one this build cannot load (UNSUPPORTED).
 * Why the old tests missed them: ED1 (b) int 0x80 from 64-bit code was run only with clean upper halves;
 * ED2 (c) 32-bit ELF runs were checked for their stop, never for what the stack held; ED3 (a) no test
 * popped into a segment register. The null-call answer and the old_mmap offset (sections 5 and 7) were
 * surviving mutants of the dispatch: (b) no test called address zero and read the answer, and every
 * old_mmap test mapped offset 0.
 *
 * SIMULATED bytes only: code written here, an ELF from hk.h.
 */
#include <kgenome.h>
#include <phenotype/emu.h>
#include <phenotype/emu_unpack.h>
#include <phenotype/emu_run_private.h>   /* the table and KGENOME_EMU_TEXT_MAX */
#include "hk.h"

#define CODE  0x400000ull
#define DATA  0x600000ull
#define STACK 0x7ff00000ull

static struct kgenome_emu *mk(unsigned bits, const uint8_t *code, unsigned n)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 100000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	kgenome_emu_map(e, CODE, code, n, 0x1000, KGENOME_EMU_R | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, NULL, 0, 0x1000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x8000u);
	kgenome_emu_set_rip(e, CODE);
	return e;
}

/* 1. The table: one entry for every width, every question answered, the conventions as the ABIs lay them. */
static void table(void)
{
	static const uint8_t i386_args[6] = { KGENOME_EMU_RBX, KGENOME_EMU_RCX, KGENOME_EMU_RDX,
					      KGENOME_EMU_RSI, KGENOME_EMU_RDI, KGENOME_EMU_RBP };
	static const uint8_t amd64_args[6] = { KGENOME_EMU_RDI, KGENOME_EMU_RSI, KGENOME_EMU_RDX,
					       KGENOME_EMU_R10, KGENOME_EMU_R8, KGENOME_EMU_R9 };
	const struct kgenome_emu_arch *x = kgenome_emu_arch_x86();
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e, *f;

	memset(&cfg, 0, sizeof cfg);
	CK(x && kgenome_emu_arch_of(NULL) == x && kgenome_emu_arch_of(&cfg) == x);
	cfg.bits = 32;
	CK(kgenome_emu_arch_of(&cfg) == x);
	CK(x->run && x->decode && x->len && x->inert && x->exec && x->text && x->tail && x->delay &&
	   x->ret_pop && x->init && x->name && !strcmp(x->name, "x86"));
	CK(x->text_max && x->text_max <= KGENOME_EMU_TEXT_MAX);
	CK(x->sp == KGENOME_EMU_RSP && x->acc == KGENOME_EMU_RAX);
	CK(x->sys[0].nr == KGENOME_EMU_RAX && x->sys[0].ret == KGENOME_EMU_RAX && x->sys[0].mask == 0xffffffffu &&
	   !memcmp(x->sys[0].arg, i386_args, 6) && x->sys[0].canon == kgenome_emu_sys_i386_nr);
	CK(x->sys[1].nr == KGENOME_EMU_RAX && x->sys[1].ret == KGENOME_EMU_RAX && x->sys[1].mask == ~(uint64_t)0 &&
	   !memcmp(x->sys[1].arg, amd64_args, 6) && x->sys[1].canon == NULL);
	/* i386 numbers to amd64: write, exit, mmap2; an unknown one cannot collide with any */
	CK(kgenome_emu_sys_i386_nr(4) == 1 && kgenome_emu_sys_i386_nr(1) == 60 && kgenome_emu_sys_i386_nr(192) == 9);
	CK(kgenome_emu_sys_i386_nr(9999) == (9999ull | (1ull << 32)));

	e = kgenome_emu_new(&cfg);
	CK(e && e->arch == x && e->bits == 32);
	/* the entry's reset state and its loader page: x86_init */
	CK(e && e->x86.mxcsr == 0x1f80u && e->x86.fcw == 0x037fu);
	{
		uint8_t v[8];

		CK(e && kgenome_emu_read(e, KGENOME_EMU_VSYSCALL_BASE, v, 8) &&
		   v[0] == 0xb8 && v[1] == 96 && v[5] == 0x0f && v[6] == 0x05 && v[7] == 0xc3);
	}
	f = e ? kgenome_emu_fork(e) : NULL;
	CK(f && f->arch == x);
	kgenome_emu_free(f);
	kgenome_emu_free(e);
	CK(kgenome_emu_run(NULL) == KGENOME_EMU_STOP_FAULT);
}

/* 2. The seed registers: every one the entry names points at the entry, the stack and frame pointers do
 *    not move, and a register the entry does not name is not touched. */
static void seed(void)
{
	static const uint8_t hlt[] = { 0xf4 };
	struct kgenome_emu *e = mk(64, hlt, sizeof hlt);
	unsigned k;

	CK(e != NULL);
	if (!e)
		return;
	kgenome_emu_set_reg(e, KGENOME_EMU_R12, 0x1234);
	kgenome_emu_arch_seed(e, 0xabcdef);
	for (k = 0; k < KGENOME_EMU_NGPR; k++) {
		uint64_t v = kgenome_emu_get_reg(e, k);

		if (k == KGENOME_EMU_RAX || k == KGENOME_EMU_RCX || k == KGENOME_EMU_RDX || k == KGENOME_EMU_RBX ||
		    k == KGENOME_EMU_RSI || k == KGENOME_EMU_RDI)
			CK(v == 0xabcdef);
		else if (k == KGENOME_EMU_RSP)
			CK(v == STACK + 0x8000u);
		else if (k == KGENOME_EMU_R12)
			CK(v == 0x1234);
		else
			CK(v == 0);
	}
	kgenome_emu_arch_seed(NULL, 1);                 /* refused, not a crash */
	kgenome_emu_free(e);
}

/* 3. ED1: the i386 convention from 64-bit code takes 32 bits of every argument register. */
static void int80_args(void)
{
	static const uint8_t code[] = {
		0xb8, 0xb5, 0x00, 0x00, 0x00,   /* mov eax, 181 (i386 pwrite64) */
		0xcd, 0x80,                     /* int 0x80                      */
		0xf4                            /* hlt                           */
	};
	struct kgenome_emu *e = mk(64, code, sizeof code);
	struct kgenome_emu_syscall s;

	CK(e != NULL);
	if (!e)
		return;
	kgenome_emu_set_reg(e, KGENOME_EMU_RBX, 0xdead00000001ull);     /* fd 1 with a stale upper half    */
	kgenome_emu_set_reg(e, KGENOME_EMU_RCX, DATA);
	kgenome_emu_set_reg(e, KGENOME_EMU_RDX, 0x100000007ull);        /* count 7 with a stale upper half */
	(void)kgenome_emu_run(e);
	CK(kgenome_emu_get_rip(e) == CODE + 7u);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 7u);              /* ED1: was 0x100000007 */
	CK(kgenome_emu_syscall_log(e, &s, 1) == 1 && s.nr == 181 && s.arg[0] == 1 && s.arg[2] == 7);
	/* the guest's own registers are its own: nothing was masked IN them */
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RDX) == 0x100000007ull);
	kgenome_emu_free(e);

	/* the amd64 convention keeps the whole register: pwrite64 is 18 */
	{
		static const uint8_t c64[] = { 0xb8, 18, 0, 0, 0, 0x0f, 0x05, 0xf4 };

		e = mk(64, c64, sizeof c64);
		CK(e != NULL);
		if (!e)
			return;
		kgenome_emu_set_reg(e, KGENOME_EMU_RDI, 1);
		kgenome_emu_set_reg(e, KGENOME_EMU_RSI, DATA);
		kgenome_emu_set_reg(e, KGENOME_EMU_RDX, 0x100000007ull);
		kgenome_emu_set_reg(e, KGENOME_EMU_R10, 0x55);
		(void)kgenome_emu_run(e);
		CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0x100000007ull);
		CK(kgenome_emu_syscall_log(e, &s, 1) == 1 && s.nr == 18 && s.arg[2] == 0x100000007ull && s.arg[3] == 0x55);
		kgenome_emu_free(e);
	}
}

/* 4. ED2: the initial stack a loader builds is made of GUEST words: argc, argv[0], NULL, envp NULL, then
 *    the auxv pairs, at 4-byte steps for a 32-bit guest and 8-byte steps for a 64-bit one. */
static void elf_stack(int is64)
{
	static const uint8_t c32[] = {
		0x8b, 0x04, 0x24,               /* mov eax, [esp]    */
		0x8b, 0x5c, 0x24, 0x04,         /* mov ebx, [esp+4]  */
		0x8b, 0x4c, 0x24, 0x08,         /* mov ecx, [esp+8]  */
		0x8b, 0x54, 0x24, 0x0c,         /* mov edx, [esp+12] */
		0x8b, 0x74, 0x24, 0x10,         /* mov esi, [esp+16] */
		0xf4
	};
	static const uint8_t c64[] = {
		0x48, 0x8b, 0x04, 0x24,
		0x48, 0x8b, 0x5c, 0x24, 0x08,
		0x48, 0x8b, 0x4c, 0x24, 0x10,
		0x48, 0x8b, 0x54, 0x24, 0x18,
		0x48, 0x8b, 0x74, 0x24, 0x20,
		0xf4
	};
	static struct hk_elf el;
	static struct kgenome_elf_info ei;
	struct kgenome_obj o;
	struct kgenome_budget bud;
	struct kgenome_emu_unp_report rep;
	struct kgenome_emu *e;
	unsigned w = is64 ? 8u : 4u, k;
	uint64_t sp, at[6] = { 3, 4, 5, 6, 9, 7 };       /* AT_PHDR PHENT PHNUM PAGESZ ENTRY BASE */
	char nm[8];

	hk_elf(&el, is64, 0, 0);
	memcpy(el.b + el.text, is64 ? c64 : c32, is64 ? sizeof c64 : sizeof c32);
	memset(&o, 0, sizeof o);
	memset(&ei, 0, sizeof ei);
	CK(kgenome_elf_image_parse(kof_buf_make(el.b, el.n), &ei, &o));
	kgenome_budget_default(&bud, el.n, el.n);
	e = kgenome_emu_unp_run(el.b, el.n, &ei, &bud, &rep);
	CK(e != NULL);
	if (!e)
		return;
	sp = kgenome_emu_get_reg(e, KGENOME_EMU_RSP);
	CK(rep.insn == 6u);
	CK(sp % 16u == 0);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 1u);                 /* argc            */
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RBX) != 0 &&                  /* argv[0]: ED2    */
	   kgenome_emu_read(e, kgenome_emu_get_reg(e, KGENOME_EMU_RBX), nm, 7) && !memcmp(nm, "/tmp/a", 7));
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RCX) == 0);                   /* argv NULL       */
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RDX) == 0);                   /* envp NULL       */
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RSI) == 3u);                  /* first auxv type */
	for (k = 0; k < 6u; k++) {
		uint64_t t = 0, v = 0;

		CK(kgenome_emu_read(e, sp + (4u + 2u * k) * w, &t, w) && t == at[k]);
		CK(kgenome_emu_read(e, sp + (5u + 2u * k) * w, &v, w));
		if (at[k] == 6u)
			CK(v == KGENOME_EMU_PAGE);
		if (at[k] == 9u)
			CK(v == rep.entry);
		if (at[k] == 4u)
			CK(v == (is64 ? 56u : 32u));
	}
	kgenome_emu_free(e);
}

/* 5. The null-call gate reads the entry's roles: a call into the unmapped first page returns to the caller
 *    through the return address the convention left, and the answer register holds 0. */
static void null_call(unsigned bits)
{
	static const uint8_t code[] = {
		0xb8, 0x55, 0x00, 0x00, 0x00,   /* mov eax, 0x55                 */
		0x31, 0xc9,                     /* xor ecx, ecx                  */
		0xff, 0xd1,                     /* call rcx / ecx: address zero  */
		0xf4                            /* hlt                           */
	};
	struct kgenome_emu *e = mk(bits, code, sizeof code);

	CK(e != NULL);
	if (!e)
		return;
	(void)kgenome_emu_run(e);
	CK(kgenome_emu_get_rip(e) == CODE + 9u);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RAX) == 0);
	CK(kgenome_emu_null_calls(e) == 1u);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RSP) == STACK + 0x8000u);    /* the return address was taken */
	kgenome_emu_free(e);
}

/* 6. ED3: `pop` into a segment register is a register this build cannot load (UNSUPPORTED, named), not a
 *    fault at address 0; a `pop` into memory nothing maps is still the guest's fault. */
static void pop_dest(void)
{
	static const uint8_t pop_fs[] = { 0x50, 0x0f, 0xa1, 0xf4 };                      /* push rax; pop fs; hlt */
	static const uint8_t pop_bad[] = { 0x50, 0x8f, 0x04, 0x25, 0x00, 0x00, 0x00, 0x7e, 0xf4 }; /* push rax; pop [0x7e000000]; hlt */
	struct kgenome_emu *e = mk(64, pop_fs, sizeof pop_fs);

	CK(e != NULL);
	if (!e)
		return;
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED);
	CK(strstr(kgenome_emu_stop_detail(e), "POP") != NULL && strstr(kgenome_emu_stop_detail(e), "fs") != NULL);
	kgenome_emu_free(e);
	e = mk(64, pop_bad, sizeof pop_bad);
	CK(e != NULL);
	if (!e)
		return;
	CK(kgenome_emu_run(e) == KGENOME_EMU_STOP_FAULT);
	CK(strstr(kgenome_emu_stop_detail(e), "write at 0x7e000000") != NULL);
	kgenome_emu_free(e);
}

/* 7. i386 old_mmap (90) reads its six arguments from memory and counts the offset in BYTES: through the
 *    convention's registers it becomes mmap2, whose offset is in pages, so the byte offset is divided on
 *    the way. A mapping of the scanned file at offset 4096 shows the file's second page. */
static void old_mmap_offset(void)
{
	static uint8_t self[8192];
	static const uint8_t code[] = { 0xb8, 0x5a, 0x00, 0x00, 0x00, 0xcd, 0x80, 0xf4 }; /* mov eax, 90; int 0x80; hlt */
	uint32_t args[6] = { 0, 4096, 1 /* PROT_READ */, 2 /* MAP_PRIVATE */, 3, 4096 };
	struct kgenome_emu *e = mk(32, code, sizeof code);
	uint8_t got[16];
	uint64_t at;
	unsigned k;

	CK(e != NULL);
	if (!e)
		return;
	for (k = 0; k < sizeof self; k++)
		self[k] = (uint8_t)(k / 4096u * 0x40u + k % 251u);
	kgenome_emu_set_self(e, self, sizeof self);
	CK(kgenome_emu_write(e, DATA, args, sizeof args));
	kgenome_emu_set_reg(e, KGENOME_EMU_RBX, DATA);
	(void)kgenome_emu_run(e);
	at = kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
	CK(at != 0 && at < 0xfffff000u && (at & 0xfffu) == 0);
	CK(kgenome_emu_read(e, at, got, sizeof got) && !memcmp(got, self + 4096, sizeof got));
	/* the guest's registers are its own: the call's six were put back */
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RBX) == DATA && kgenome_emu_get_reg(e, KGENOME_EMU_RBP) == 0);
	kgenome_emu_free(e);
}

/* 8. The loop's ends of an instruction the entry does not carry out: bytes that are no instruction (DECODE),
 *    a privileged one (FAULT, named), one this build does not implement (UNSUPPORTED, named by its text). */
static void refusals(void)
{
	static const uint8_t bad[] = { 0x0f, 0x04 };            /* no instruction in 64-bit mode */
	static const uint8_t cli[] = { 0xfa };
	static const uint8_t hlt[] = { 0xf4 };
	struct kgenome_emu *e = mk(64, bad, sizeof bad);

	CK(e && kgenome_emu_run(e) == KGENOME_EMU_STOP_DECODE && kgenome_emu_get_rip(e) == CODE);
	kgenome_emu_free(e);
	e = mk(64, cli, sizeof cli);
	CK(e && kgenome_emu_run(e) == KGENOME_EMU_STOP_FAULT && strstr(kgenome_emu_stop_detail(e), "priv") != NULL);
	kgenome_emu_free(e);
	e = mk(64, hlt, sizeof hlt);
	CK(e && kgenome_emu_run(e) == KGENOME_EMU_STOP_UNSUPPORTED && strstr(kgenome_emu_stop_detail(e), "HLT") != NULL);
	kgenome_emu_free(e);
}

int main(void)
{
	table();
	seed();
	int80_args();
	elf_stack(0);
	elf_stack(1);
	null_call(32);
	null_call(64);
	pop_dest();
	old_mmap_offset();
	refusals();
	if (hk_fails)
		printf("emu_dispatch: FAIL\n");
	else
		printf("emu_dispatch: ok\n");
	return hk_fails != 0;
}
