/*
 * xref_shapes - the shapes the code sweep must tell apart.
 *
 * The discriminator this file guards is the one thing a payload finder cannot
 * get from the bytes of a payload: an ordinary variable is READ, and a payload
 * is EXECUTED. Encoding the payload defeats every test of its contents and
 * defeats none of this, because the evidence is in the code.
 *
 * WRITTEN AS INSTRUCTIONS AND NOT AS FILES. The controls were four small C
 * programs compiled on the spot, which made the test depend on a compiler, on
 * its optimiser, and on a scratch directory - and the scratch directory is
 * where they were when they were lost. What is actually under test is a
 * sequence of instructions, so that is what is written here; each was checked
 * against objdump before being pasted in, and the disassembly is in the comment
 * beside it.
 *
 * The negative controls matter as much as the positive ones. A rule that
 * answered CALL for everything would pass three of these five.
 */
#include <stdio.h>
#include <string.h>

#include "../../libkofeng/kofdisasm/xref.h"

static int fails;

#define CODE_VA 0x1000u
#define DATA_VA 0x4000u

static void expect(const char *tag, const uint8_t *code, uint32_t n,
		   uint32_t want, uint32_t must_not)
{
	struct kof_xref *u = kof_xref_new();
	uint32_t got;

	if (!u) {
		printf("  FAIL %s: out of memory\n", tag);
		fails++;
		return;
	}
	kof_xref_add(u, code, n, CODE_VA, 64);
	got = kof_xref_in(u, DATA_VA, 8);
	if ((got & want) != want) {
		printf("  FAIL %s: wanted 0x%x, got 0x%x\n", tag, want, got);
		fails++;
	} else if (got & must_not) {
		printf("  FAIL %s: must not have 0x%x, got 0x%x\n", tag,
		       must_not, got);
		fails++;
	}
	kof_xref_free(u);
}

int main(void)
{
	/*
	 *   lea  rax, [rip+0x2ff9]      # 0x4000
	 *   call rax
	 * The address itself is executed - an array cast to a function.
	 */
	static const uint8_t lea_call[] = {
		0x48,0x8d,0x05,0xf9,0x2f,0x00,0x00, 0xff,0xd0, 0xc3
	};
	/*
	 *   mov  rax, [rip+0x2ff9]      # 0x4000
	 *   mov  [rbp-8], rax
	 *   mov  rax, [rbp-8]
	 *   call rax
	 * What gcc -O0 emits for a local function pointer: the trail runs
	 * through one stack slot, and without the slot map it ends at the store.
	 */
	static const uint8_t via_stack[] = {
		0x48,0x8b,0x05,0xf9,0x2f,0x00,0x00,
		0x48,0x89,0x45,0xf8, 0x48,0x8b,0x45,0xf8, 0xff,0xd0, 0xc3
	};
	/*
	 *   call 0x4000
	 * What gcc -O2 emits for the same source: the target is a constant, so
	 * the call is direct - and it names a variable, which is exactly the
	 * case a rule saying "direct calls name code" would miss.
	 */
	static const uint8_t direct[] = { 0xe8,0xfb,0x2f,0x00,0x00, 0xc3 };
	/*
	 *   mov  rax, [rip+0x2ff9]      # 0x4000
	 *   mov  rdi, rax
	 *   call 0x1023                 (code, not data)
	 * Read and handed to a function. ARG, and NOT executed - the negative
	 * control that matters, because every loader shape also sets ARG.
	 */
	static const uint8_t as_arg[] = {
		0x48,0x8b,0x05,0xf9,0x2f,0x00,0x00,
		0x48,0x89,0xc7, 0xe8,0x14,0x00,0x00,0x00, 0xc3
	};
	/*
	 *   mov  rax, [rip+0x2ff9]      # 0x4000
	 *   ret
	 * A lookup table. Read, and nothing else.
	 */
	static const uint8_t read_only[] = {
		0x48,0x8b,0x05,0xf9,0x2f,0x00,0x00, 0xc3
	};

	expect("lea+call",  lea_call,  (uint32_t)sizeof lea_call,
	       KOF_XREF_READ | KOF_XREF_CALL, 0);
	expect("via_stack", via_stack, (uint32_t)sizeof via_stack,
	       KOF_XREF_READ | KOF_XREF_CALL, 0);
	expect("direct",    direct,    (uint32_t)sizeof direct,
	       KOF_XREF_READ | KOF_XREF_CALL, 0);
	expect("as_arg",    as_arg,    (uint32_t)sizeof as_arg,
	       KOF_XREF_READ | KOF_XREF_ARG, KOF_XREF_CALL | KOF_XREF_JUMP);
	expect("read_only", read_only, (uint32_t)sizeof read_only,
	       KOF_XREF_READ, KOF_XREF_CALL | KOF_XREF_JUMP | KOF_XREF_ARG);

	/*
	 * AND THE RANGE, which is not a detail: a blob is not referred to at its
	 * first byte. gcc -O0 copying a 23 byte array reads it at +0, +8 and
	 * +15, so a query on the first address alone finds one of the three and
	 * would find none had the compiler started anywhere else.
	 */
	{
		/* mov rax,[rip+0x3001]  # 0x4008 - the MIDDLE of the variable */
		static const uint8_t mid[] = {
			0x48,0x8d,0x05,0x01,0x30,0x00,0x00, 0xff,0xd0, 0xc3
		};
		struct kof_xref *u = kof_xref_new();

		if (u) {
			kof_xref_add(u, mid, (uint32_t)sizeof mid, CODE_VA, 64);
			if (kof_xref_in(u, DATA_VA, 1) & KOF_XREF_CALL) {
				printf("  FAIL range: a one byte query saw an "
				       "xref eight bytes away\n");
				fails++;
			}
			if (!(kof_xref_in(u, DATA_VA, 32) & KOF_XREF_CALL)) {
				printf("  FAIL range: a 32 byte query missed an "
				       "xref inside it\n");
				fails++;
			}
			kof_xref_free(u);
		}
	}

	printf("xref shapes: %s\n",
	       fails ? "FAILED" : "call, stack, direct, arg, read, range - ok");
	return fails != 0;
}
