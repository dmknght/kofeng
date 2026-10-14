/*
 * cov_emu_exc - exceptions in a Windows guest: vectored handlers, the SEH chain and the top level filter.
 *
 * A protector installs a handler and then faults on purpose: the handler edits the CONTEXT it is given and says "carry on".
 * The interpreter builds the EXCEPTION_RECORD and the CONTEXT where Windows would, calls the guest's handler as a
 * function, and resumes from the CONTEXT when the answer is "continue". This test is the guest:
 *
 *   VEH         a handler that stores the exception code and the faulting address it was given, moves RIP past the
 *               instruction in the CONTEXT and returns -1: the guest goes on, and what the handler read is what the
 *               architecture's record layout says (code at 0, the access kind and address in the information array)
 *   ORDER       two handlers, the first registered "first" runs first; one that declines (0) hands over to the next;
 *               all decline: the run ends where the fault was, with the fault named
 *   READ, WRITE the access kind in the record is 0 for a read and 1 for a write
 *   SEH         (32 bit) the FS:[0] chain: the handler takes (record, frame, context, dispatcher) and returns 0 to continue;
 *               a handler that returns 1 hands over to the previous frame; a chain that loops back on itself is bounded
 *   FILTER      SetUnhandledExceptionFilter's function, called last, with its own return numbering (-1 continues)
 *   BOUNDS      a handler that faults in its own body is dispatched a bounded number of levels deep and then the run ends
 *   COUNTS      kgenome_emu_exc_counts says how many faults were offered, how many a handler took, how many VEHs there are
 *   #DE         a divide by zero and a quotient overflow arrive as STATUS_INTEGER_DIVIDE_BY_ZERO and STATUS_INTEGER_OVERFLOW
 *               and, with nobody to take them, end the run as a FAULT that names the divide
 *
 * The 64 bit table SEH (.pdata) is documented as absent; that a 64 bit guest with only a table handler stops is asserted.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <phenotype/emu.h>

static int fails;

#define CK(cond, ...) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  ", __FILE__, __LINE__); \
		printf(__VA_ARGS__); \
		printf("\n"); \
		fails++; \
	} \
} while (0)

#define CODE   0x400000ull
#define HAND   0x400400ull
#define HAND2  0x400500ull
#define DATA   0x600000ull
#define STACK  0x7ff00000ull
#define TEB    0x60f000ull
#define BAD    0x7e000000ull          /* unmapped, and not the null page (which reads as zeros) */

static struct kgenome_emu *mk(unsigned bits)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	unsigned i, n = kgenome_emu_win_api_count();

	memset(&cfg, 0, sizeof cfg);
	cfg.bits = bits;
	cfg.max_insn = 200000;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		kgenome_emu_win_set_module(e, i, kgenome_emu_win_mod_base(i, bits));
	kgenome_emu_win_setup(e, bits == 32 ? 0x400000ull : 0x140000000ull);
	for (i = 0; i < kgenome_emu_win_mod_count(); i++)
		kgenome_emu_map(e, kgenome_emu_win_mod_base(i, bits) + KGENOME_EMU_WIN_STUB_RVA, NULL, 0, 0x8000,
				KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	for (i = 0; i < n; i++) {
		uint64_t a = kgenome_emu_win_addr_of(e, kgenome_emu_win_api_name(i));
		uint8_t stub[16];
		unsigned argc = kgenome_emu_win_api_argc(i);
		uint32_t trap = kgenome_emu_win_api_trap(i);

		if (!a)
			continue;
		memset(stub, 0xcc, sizeof stub);
		stub[0] = 0xb8;
		memcpy(stub + 1, &trap, 4);
		if (bits == 32) {
			stub[5] = 0xcd; stub[6] = 0x80;
			if (argc) {
				uint16_t pop = (uint16_t)(argc * 4u);

				stub[7] = 0xc2;
				memcpy(stub + 8, &pop, 2);
			} else {
				stub[7] = 0xc3;
			}
		} else {
			stub[5] = 0x0f; stub[6] = 0x05; stub[7] = 0xc3;
		}
		kgenome_emu_write(e, a, stub, sizeof stub);
	}
	kgenome_emu_map(e, CODE, NULL, 0, 0x2000, KGENOME_EMU_R | KGENOME_EMU_W | KGENOME_EMU_X);
	kgenome_emu_map(e, DATA, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, STACK, NULL, 0, 0x10000, KGENOME_EMU_R | KGENOME_EMU_W);
	return e;
}

/* run `code` at CODE until it stops; returns the stop */
static enum kgenome_emu_stop run_at(struct kgenome_emu *e, const uint8_t *code, unsigned n, uint64_t rip)
{
	kgenome_emu_write(e, CODE, code, n);
	kgenome_emu_set_rip(e, rip);
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, STACK + 0x8000);
	return kgenome_emu_run(e);
}

/* call an API through its stub with up to two arguments (64 bit: rcx, rdx; 32 bit: pushed) */
static uint64_t api(struct kgenome_emu *e, unsigned bits, const char *name, uint64_t a, uint64_t b)
{
	uint8_t c[64];
	unsigned n = 0;
	uint64_t stub = kgenome_emu_win_addr_of(e, name);

	if (bits == 64) {
		c[n++] = 0x48; c[n++] = 0xb9; memcpy(c + n, &a, 8); n += 8;
		c[n++] = 0x48; c[n++] = 0xba; memcpy(c + n, &b, 8); n += 8;
		c[n++] = 0x48; c[n++] = 0xb8; memcpy(c + n, &stub, 8); n += 8;
		c[n++] = 0xff; c[n++] = 0xd0;
	} else {
		uint32_t x = (uint32_t)b, y = (uint32_t)a, s = (uint32_t)stub;

		c[n++] = 0x68; memcpy(c + n, &x, 4); n += 4;
		c[n++] = 0x68; memcpy(c + n, &y, 4); n += 4;
		c[n++] = 0xb8; memcpy(c + n, &s, 4); n += 4;
		c[n++] = 0xff; c[n++] = 0xd0;
	}
	c[n++] = 0xf4;
	run_at(e, c, n, CODE);
	return kgenome_emu_get_reg(e, KGENOME_EMU_RAX);
}

static uint64_t get(struct kgenome_emu *e, uint64_t va, unsigned n)
{
	uint64_t v = 0;

	if (!kgenome_emu_read(e, va, &v, n))
		return 0xdeadbeefdeadbeefull;
	return v;
}

/* the 64 bit handlers: store code (+0) and information[0], [1] to DATA, edit rip, return `ret` */
static unsigned h64(uint8_t *c, int32_t skip, uint32_t ret, uint32_t marker_off)
{
	unsigned n = 0;
	const uint8_t a[] = { 0x48, 0x8b, 0x01 };                      /* mov rax,[rcx]        EXCEPTION_RECORD* */
	const uint8_t b[] = { 0x8b, 0x00 };                            /* mov eax,[rax]        the code */
	const uint8_t d[] = { 0x49, 0xbb };                            /* mov r11, imm64 */
	uint64_t data = DATA + marker_off;

	memcpy(c + n, a, 3); n += 3;
	/* keep the record pointer: mov rdx, rax before the load of the code */
	c[n++] = 0x48; c[n++] = 0x89; c[n++] = 0xc2;                   /* mov rdx, rax */
	memcpy(c + n, b, 2); n += 2;
	memcpy(c + n, d, 2); n += 2;
	memcpy(c + n, &data, 8); n += 8;
	c[n++] = 0x41; c[n++] = 0x89; c[n++] = 0x03;                   /* mov [r11], eax */
	c[n++] = 0x48; c[n++] = 0x8b; c[n++] = 0x42; c[n++] = 0x28;    /* mov rax,[rdx+0x28]   information[1]: the address */
	c[n++] = 0x49; c[n++] = 0x89; c[n++] = 0x43; c[n++] = 0x08;    /* mov [r11+8], rax */
	c[n++] = 0x48; c[n++] = 0x8b; c[n++] = 0x42; c[n++] = 0x20;    /* mov rax,[rdx+0x20]   information[0]: read 0, write 1 */
	c[n++] = 0x49; c[n++] = 0x89; c[n++] = 0x43; c[n++] = 0x10;    /* mov [r11+16], rax */
	c[n++] = 0x48; c[n++] = 0x8b; c[n++] = 0x41; c[n++] = 0x08;    /* mov rax,[rcx+8]      CONTEXT* */
	c[n++] = 0x48; c[n++] = 0x83; c[n++] = 0x80;                   /* add qword [rax+0xf8], imm8 */
	c[n++] = 0xf8; c[n++] = 0x00; c[n++] = 0x00; c[n++] = 0x00; c[n++] = (uint8_t)skip;
	c[n++] = 0xb8; memcpy(c + n, &ret, 4); n += 4;                 /* mov eax, ret */
	c[n++] = 0xc3;
	return n;
}

/* mov rax,[BAD] ; mov r10, 0x1234 ; hlt  - and the write form */
static unsigned fault_read(uint8_t *c)
{
	unsigned n = 0;
	uint64_t m = 0x1234;

	c[n++] = 0x48; c[n++] = 0x8b; c[n++] = 0x04; c[n++] = 0x25;           /* mov rax,[abs32] (8 bytes) */
	c[n++] = (uint8_t)BAD; c[n++] = (uint8_t)(BAD >> 8); c[n++] = (uint8_t)(BAD >> 16); c[n++] = (uint8_t)(BAD >> 24);
	c[n++] = 0x49; c[n++] = 0xba; memcpy(c + n, &m, 8); n += 8;           /* mov r10, 0x1234 */
	c[n++] = 0xf4;
	return n;
}

static unsigned fault_write(uint8_t *c)
{
	unsigned n = 0;
	uint64_t m = 0x1234;

	c[n++] = 0x48; c[n++] = 0x89; c[n++] = 0x04; c[n++] = 0x25;           /* mov [abs32], rax (8 bytes) */
	c[n++] = (uint8_t)BAD; c[n++] = (uint8_t)(BAD >> 8); c[n++] = (uint8_t)(BAD >> 16); c[n++] = (uint8_t)(BAD >> 24);
	c[n++] = 0x49; c[n++] = 0xba; memcpy(c + n, &m, 8); n += 8;
	c[n++] = 0xf4;
	return n;
}

static void t_veh(void)
{
	struct kgenome_emu *e = mk(64);
	uint8_t code[64], hand[160];
	unsigned n, hn;
	uint32_t raised = 0, taken = 0, veh = 0;
	enum kgenome_emu_stop st;

	if (!e) {
		CK(0, "emulator");
		return;
	}
	hn = h64(hand, 8, 0xffffffffu, 0);
	kgenome_emu_write(e, HAND, hand, hn);
	CK(api(e, 64, "AddVectoredExceptionHandler", 1, HAND) == HAND, "the handler is registered");
	n = fault_read(code);
	st = run_at(e, code, n, CODE);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0x1234, "the guest went on after the fault (r10 %#llx, stop %s)",
	   (unsigned long long)kgenome_emu_get_reg(e, KGENOME_EMU_R10), kgenome_emu_stop_name(st));
	CK(get(e, DATA, 4) == 0xc0000005u, "the handler saw EXCEPTION_ACCESS_VIOLATION (%#llx)", (unsigned long long)get(e, DATA, 4));
	CK(get(e, DATA + 8, 8) == BAD, "and the faulting address %#llx (%#llx)", (unsigned long long)BAD, (unsigned long long)get(e, DATA + 8, 8));
	CK(get(e, DATA + 16, 8) == 0, "a read: information[0] is 0");
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 1 && taken == 1 && veh == 1, "counts: raised %u taken %u handlers %u", raised, taken, veh);

	/* a write */
	memset(code, 0, sizeof code);
	n = fault_write(code);
	kgenome_emu_set_reg(e, KGENOME_EMU_R10, 0);
	run_at(e, code, n, CODE);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0x1234, "the guest went on after a write fault");
	CK(get(e, DATA + 16, 8) == 1, "a write: information[0] is 1");
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 2 && taken == 2, "counts after the second: raised %u taken %u", raised, taken);
	kgenome_emu_free(e);

	/* a handler that declines: nobody took it, the run ends where the fault was */
	e = mk(64);
	hn = h64(hand, 8, 0, 0);
	kgenome_emu_write(e, HAND, hand, hn);
	api(e, 64, "AddVectoredExceptionHandler", 1, HAND);
	n = fault_read(code);
	st = run_at(e, code, n, CODE);
	CK(st == KGENOME_EMU_STOP_FAULT && kgenome_emu_get_reg(e, KGENOME_EMU_R10) != 0x1234,
	   "a declined fault ends the run as a fault (%s)", kgenome_emu_stop_name(st));
	CK(get(e, DATA, 4) == 0xc0000005u, "the handler had been asked");
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 1 && taken == 0, "counts: raised %u taken %u", raised, taken);
	kgenome_emu_free(e);

	/* two handlers: the one registered first-called runs first, a decline hands over to the second */
	e = mk(64);
	hn = h64(hand, 0, 0, 0x100);                 /* declines, and leaves the CONTEXT alone */
	kgenome_emu_write(e, HAND, hand, hn);
	hn = h64(hand, 8, 0xffffffffu, 0x200);
	kgenome_emu_write(e, HAND2, hand, hn);
	CK(api(e, 64, "AddVectoredExceptionHandler", 0, HAND2) == HAND2, "the taking handler is registered last");
	CK(api(e, 64, "AddVectoredExceptionHandler", 1, HAND) == HAND, "the declining one is registered first-called");
	n = fault_read(code);
	st = run_at(e, code, n, CODE);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0x1234, "the second handler took it and the guest went on (%s)", kgenome_emu_stop_name(st));
	CK(get(e, DATA + 0x100, 4) == 0xc0000005u && get(e, DATA + 0x200, 4) == 0xc0000005u, "both were called");
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 1 && taken == 1 && veh == 2, "counts: raised %u taken %u handlers %u", raised, taken, veh);
	/* removed: the fault is unhandled */
	CK(api(e, 64, "RemoveVectoredExceptionHandler", HAND2, 0) == 1, "the taking handler is removed");
	n = fault_read(code);
	kgenome_emu_set_reg(e, KGENOME_EMU_R10, 0);
	st = run_at(e, code, n, CODE);
	CK(st == KGENOME_EMU_STOP_FAULT && kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0, "with it gone the fault ends the run (%s)",
	   kgenome_emu_stop_name(st));
	kgenome_emu_free(e);

	/* the top level filter: called last, -1 continues; the same return numbering the filter has */
	e = mk(64);
	hn = h64(hand, 8, 0xffffffffu, 0x300);
	kgenome_emu_write(e, HAND, hand, hn);
	CK(api(e, 64, "SetUnhandledExceptionFilter", HAND, 0) == 0, "no previous filter");
	n = fault_read(code);
	st = run_at(e, code, n, CODE);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0x1234 && get(e, DATA + 0x300, 4) == 0xc0000005u,
	   "the top level filter took it and the guest went on (%s)", kgenome_emu_stop_name(st));
	kgenome_emu_free(e);
	e = mk(64);
	hn = h64(hand, 8, 1, 0x300);                    /* EXCEPTION_EXECUTE_HANDLER: the process is ending */
	kgenome_emu_write(e, HAND, hand, hn);
	api(e, 64, "SetUnhandledExceptionFilter", HAND, 0);
	n = fault_read(code);
	st = run_at(e, code, n, CODE);
	CK(st == KGENOME_EMU_STOP_FAULT && kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0, "a filter that says EXECUTE_HANDLER ends the run (%s)",
	   kgenome_emu_stop_name(st));
	kgenome_emu_free(e);

	/* a handler that faults inside its own body: dispatched a bounded number of levels, then the run ends */
	e = mk(64);
	{
		uint8_t loop[16];
		unsigned k = 0;

		loop[k++] = 0x48; loop[k++] = 0x8b; loop[k++] = 0x04; loop[k++] = 0x25;
		loop[k++] = (uint8_t)BAD; loop[k++] = (uint8_t)(BAD >> 8); loop[k++] = (uint8_t)(BAD >> 16); loop[k++] = (uint8_t)(BAD >> 24);
		loop[k++] = 0xc3;
		kgenome_emu_write(e, HAND, loop, k);
		api(e, 64, "AddVectoredExceptionHandler", 1, HAND);
		n = fault_read(code);
		st = run_at(e, code, n, CODE);
		kgenome_emu_exc_counts(e, &raised, &taken, &veh);
		CK(st == KGENOME_EMU_STOP_FAULT, "a handler that faults in itself ends the run (%s)", kgenome_emu_stop_name(st));
		CK(raised >= 2 && raised <= 8, "after a bounded number of nested dispatches (%u)", raised);
	}
	kgenome_emu_free(e);

	/* a 64 bit guest with no vectored handler and no filter: table SEH is absent, the run stops at the fault */
	e = mk(64);
	n = fault_read(code);
	st = run_at(e, code, n, CODE);
	CK(st == KGENOME_EMU_STOP_FAULT, "no handler at all: the fault stops the run (%s)", kgenome_emu_stop_name(st));
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 1 && taken == 0 && veh == 0, "counts: %u %u %u", raised, taken, veh);
	CK(kgenome_emu_exc_scratch(e, &(uint64_t){ 0 }) != 0, "the records were built where the harvest can leave them alone");
	kgenome_emu_free(e);
}


/*
 * #DE: a divide by zero and a quotient that does not fit are faults like any other. A vectored handler is given
 * STATUS_INTEGER_DIVIDE_BY_ZERO (0xc0000094) or STATUS_INTEGER_OVERFLOW (0xc0000095), moves RIP past the DIV in the CONTEXT and
 * the guest goes on; with nobody to take it the run ends with a FAULT stop that names the divide - never UNSUPPORTED, which
 * says "an instruction this build lacks" and was what both used to be. (The Linux guest, which has no signal delivery here,
 * ends the same way: tests/lib/genome/cov_emu_int.c.)
 */
static unsigned de_code(uint8_t *c, int overflow)
{
	unsigned n = 0;
	const uint64_t m = 0x1234;

	if (!overflow) {
		c[n++] = 0xb8; c[n++] = 5; c[n++] = 0; c[n++] = 0; c[n++] = 0;                 /* mov eax,5 */
		c[n++] = 0x31; c[n++] = 0xd2;                                                   /* xor edx,edx */
		c[n++] = 0x31; c[n++] = 0xc9;                                                   /* xor ecx,ecx */
	} else {
		c[n++] = 0x31; c[n++] = 0xc0;                                                   /* xor eax,eax */
		c[n++] = 0xba; c[n++] = 3; c[n++] = 0; c[n++] = 0; c[n++] = 0;                 /* mov edx,3 */
		c[n++] = 0xb9; c[n++] = 3; c[n++] = 0; c[n++] = 0; c[n++] = 0;                 /* mov ecx,3: edx >= ecx */
	}
	c[n++] = 0xf7; c[n++] = 0xf1;                                                       /* div ecx */
	c[n++] = 0x49; c[n++] = 0xba; memcpy(c + n, &m, 8); n += 8;                         /* mov r10,0x1234 */
	c[n++] = 0xf4;
	return n;
}

static void t_de(void)
{
	unsigned ov;

	for (ov = 0; ov < 2; ov++) {
		struct kgenome_emu *e = mk(64);
		uint8_t code[64], hand[160];
		unsigned n, hn;
		uint32_t raised = 0, taken = 0, veh = 0;
		enum kgenome_emu_stop st;

		if (!e) {
			CK(0, "emulator");
			return;
		}
		hn = h64(hand, 2, 0xffffffffu, 0);
		kgenome_emu_write(e, HAND, hand, hn);
		CK(api(e, 64, "AddVectoredExceptionHandler", 1, HAND) == HAND, "the handler is registered");
		n = de_code(code, (int)ov);
		st = run_at(e, code, n, CODE);
		CK(kgenome_emu_get_reg(e, KGENOME_EMU_R10) == 0x1234, "the guest went on after the divide (r10 %#llx, stop %s)",
		   (unsigned long long)kgenome_emu_get_reg(e, KGENOME_EMU_R10), kgenome_emu_stop_name(st));
		CK(get(e, DATA, 4) == (ov ? 0xc0000095u : 0xc0000094u), "the handler saw %s (%#llx)",
		   ov ? "STATUS_INTEGER_OVERFLOW" : "STATUS_INTEGER_DIVIDE_BY_ZERO", (unsigned long long)get(e, DATA, 4));
		kgenome_emu_exc_counts(e, &raised, &taken, &veh);
		CK(raised == 1 && taken == 1, "counts: raised %u taken %u", raised, taken);
		kgenome_emu_free(e);

		e = mk(64);                                     /* nobody to take it */
		n = de_code(code, (int)ov);
		st = run_at(e, code, n, CODE);
		CK(st == KGENOME_EMU_STOP_FAULT && kgenome_emu_get_reg(e, KGENOME_EMU_R10) != 0x1234,
		   "with no handler the divide ends the run as a fault (%s)", kgenome_emu_stop_name(st));
		CK(strstr(kgenome_emu_stop_detail(e), ov ? "divovf" : "divzero") != NULL, "and says which: %s", kgenome_emu_stop_detail(e));
		kgenome_emu_free(e);
	}
}

/* ---- 32 bit: the SEH chain --------------------------------------------------------------------- */

static void t_seh(void)
{
	struct kgenome_emu *e = mk(32);
	uint8_t code[64], hand[64];
	unsigned n = 0, hn = 0;
	uint32_t raised = 0, taken = 0, veh = 0;
	enum kgenome_emu_stop st;
	uint32_t reg[2];

	if (!e) {
		CK(0, "emulator");
		return;
	}
	/* mov eax,[BAD] (5 bytes) ; mov ebx, 0x1234 ; hlt */
	code[n++] = 0xa1; code[n++] = (uint8_t)BAD; code[n++] = (uint8_t)(BAD >> 8); code[n++] = (uint8_t)(BAD >> 16); code[n++] = (uint8_t)(BAD >> 24);
	code[n++] = 0xbb; code[n++] = 0x34; code[n++] = 0x12; code[n++] = 0; code[n++] = 0;
	code[n++] = 0xf4;
	/* handler: cdecl(record, frame, context, dispatcher): add [context+0xb8], 5 ; xor eax,eax ; ret */
	hand[hn++] = 0x8b; hand[hn++] = 0x44; hand[hn++] = 0x24; hand[hn++] = 0x0c;        /* mov eax,[esp+12] */
	hand[hn++] = 0x83; hand[hn++] = 0x80; hand[hn++] = 0xb8; hand[hn++] = 0; hand[hn++] = 0; hand[hn++] = 0; hand[hn++] = 0x05;
	hand[hn++] = 0x31; hand[hn++] = 0xc0;                                                /* xor eax,eax: ExceptionContinueExecution */
	hand[hn++] = 0xc3;
	kgenome_emu_write(e, HAND, hand, hn);
	/* the thread block: FS:[0] is the head of the chain, one registration whose handler is HAND */
	reg[0] = 0xffffffffu;
	reg[1] = (uint32_t)HAND;
	kgenome_emu_write(e, DATA + 0x800, reg, 8);
	{
		uint32_t head = (uint32_t)(DATA + 0x800);

		kgenome_emu_write(e, TEB, &head, 4);
	}
	kgenome_emu_set_seg_base(e, 4, TEB);
	st = run_at(e, code, n, CODE);
	CK(kgenome_emu_get_reg(e, KGENOME_EMU_RBX) == 0x1234, "the SEH handler took it and the guest went on (ebx %#llx, %s)",
	   (unsigned long long)kgenome_emu_get_reg(e, KGENOME_EMU_RBX), kgenome_emu_stop_name(st));
	kgenome_emu_exc_counts(e, &raised, &taken, &veh);
	CK(raised == 1 && taken == 1, "counts: raised %u taken %u", raised, taken);
	kgenome_emu_free(e);

	/* the first frame declines (ExceptionContinueSearch = 1), the previous one takes it */
	e = mk(32);
	{
		uint8_t decline[8] = { 0xb8, 1, 0, 0, 0, 0xc3 };
		uint32_t f_outer[2] = { 0xffffffffu, (uint32_t)HAND }, f_inner[2] = { (uint32_t)(DATA + 0x800), (uint32_t)HAND2 };
		uint32_t head = (uint32_t)(DATA + 0x820);

		kgenome_emu_write(e, HAND, hand, hn);
		kgenome_emu_write(e, HAND2, decline, 6);
		kgenome_emu_write(e, DATA + 0x800, f_outer, 8);
		kgenome_emu_write(e, DATA + 0x820, f_inner, 8);
		kgenome_emu_write(e, TEB, &head, 4);
		kgenome_emu_set_seg_base(e, 4, TEB);
		st = run_at(e, code, n, CODE);
		CK(kgenome_emu_get_reg(e, KGENOME_EMU_RBX) == 0x1234, "a frame that declines hands over to the previous one (%s)", kgenome_emu_stop_name(st));
	}
	kgenome_emu_free(e);

	/* a chain that loops back on itself, every handler declining: bounded */
	e = mk(32);
	{
		uint8_t decline[8] = { 0xb8, 1, 0, 0, 0, 0xc3 };
		uint32_t f[2] = { (uint32_t)(DATA + 0x800), (uint32_t)HAND };
		uint32_t head = (uint32_t)(DATA + 0x800);

		kgenome_emu_write(e, HAND, decline, 6);
		kgenome_emu_write(e, DATA + 0x800, f, 8);
		kgenome_emu_write(e, TEB, &head, 4);
		kgenome_emu_set_seg_base(e, 4, TEB);
		st = run_at(e, code, n, CODE);
		kgenome_emu_exc_counts(e, &raised, &taken, &veh);
		CK(st == KGENOME_EMU_STOP_FAULT && taken == 0, "a chain that loops ends the run, unhandled (%s, taken %u)", kgenome_emu_stop_name(st), taken);
	}
	kgenome_emu_free(e);

	/* a chain whose handler address is zero or unreadable: nothing to call */
	e = mk(32);
	{
		uint32_t f[2] = { 0xffffffffu, 0 };
		uint32_t head = (uint32_t)(DATA + 0x800);

		kgenome_emu_write(e, DATA + 0x800, f, 8);
		kgenome_emu_write(e, TEB, &head, 4);
		kgenome_emu_set_seg_base(e, 4, TEB);
		st = run_at(e, code, n, CODE);
		CK(st == KGENOME_EMU_STOP_FAULT, "a registration with no handler: the fault stops the run (%s)", kgenome_emu_stop_name(st));
	}
	kgenome_emu_free(e);
}

int main(void)
{
	t_veh();
	t_de();
	t_seh();
	if (fails) {
		printf("cov_emu_exc: FAILED (%d)\n", fails);
		return 1;
	}
	printf("cov_emu_exc: ok\n");
	return 0;
}
