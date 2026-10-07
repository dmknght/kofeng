/*
 * diag_wrap - a syscall whose argument is the CALLER'S.
 *
 * uClibc wraps i386's socketcall in one function that loads the sub-call from
 * its own parameter, so at the `int 0x80` the sub-call is unknown and at each
 * call to the function it is a constant. Before this, the site was dropped
 * without a word: MEASURED, 27 of 30 static i386 IoT bots had the instruction
 * and not one net node between them.
 *
 * WHY A TEST AND NOT A CORPUS RUN. A corpus says how many nodes appeared. It
 * cannot say that the node for connect sits on the call that PUSHED 3, that a
 * call pushing nothing got no node, or that an unresolvable site is reported
 * as unknown instead of being dropped again.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/detectors/pathogen/kofdiag.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

static void put32(uint8_t *b, unsigned at, uint32_t v)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
static void put16(uint8_t *b, unsigned at, uint16_t v)
{
	b[at] = (uint8_t)v;
	b[at + 1u] = (uint8_t)(v >> 8);
}

/* A 32-bit ELF whose one executable segment holds `code`, entry at +0x54. */
static uint64_t elf32(uint8_t *b, uint64_t cap, const uint8_t *code, uint64_t n)
{
	memset(b, 0, (size_t)cap);
	memcpy(b, "\177ELF\1\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 3);                /* EM_386  */
	put32(b, 20, 1);
	put32(b, 24, 0x8048054u);
	put32(b, 28, 52);
	put16(b, 40, 52);
	put16(b, 42, 32);
	put16(b, 44, 1);
	put32(b, 52, 1);                /* PT_LOAD */
	put32(b, 56, 0);
	put32(b, 60, 0x8048000u);
	put32(b, 68, (uint32_t)(0x54u + n));
	put32(b, 72, (uint32_t)(0x54u + n));
	put32(b, 76, 5);                /* R-X     */
	memcpy(b + 0x54, code, (size_t)n);
	return 0x54u + n;
}

static unsigned char view[1u << 21];

static struct kof_diag_scan *scan(const uint8_t *b, uint64_t n,
				  struct kof_obj_ctx *ctx, const char *what)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	buf.p = b;
	buf.n = n;
	memset(ctx, 0, sizeof *ctx);
	memset(view, 0, sizeof view);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, ctx))
			/* THE SYSCALL ROUTINE AND ONLY IT. These cases are
			 * about which byte sequences count as a way into
			 * the kernel, which is that routine's rule; a node
			 * from a run would be a different question counted
			 * in the same total. */
			return kof_diag_scan_with(ctx, b, n,
						  KOF_DIAG_RUN_SYSCALL);
	printf("  FAIL %s: the engine did not parse it\n", what);
	fails++;
	return NULL;
}


static uint32_t count(struct kof_diag_scan *s)
{
	return s ? kof_diag_scan_count(s) : 0;
}

/* the wrapper, as uClibc builds it: call = [esp+4], args = [esp+8] */
static const uint8_t wrapper[] = {
	0x53,                               /* push ebx            */
	0x83, 0xec, 0x08,                   /* sub esp,8           */
	0x8b, 0x54, 0x24, 0x10,             /* mov edx,[esp+0x10]  */
	0x8b, 0x4c, 0x24, 0x14,             /* mov ecx,[esp+0x14]  */
	0x87, 0xd3,                         /* xchg ebx,edx        */
	0xb8, 0x66, 0x00, 0x00, 0x00,       /* mov eax,0x66        */
	0xcd, 0x80,                         /* int 0x80            */
	0x87, 0xd3,                         /* xchg ebx,edx        */
	0x83, 0xc4, 0x08,                   /* add esp,8           */
	0x5b,                               /* pop ebx             */
	0xc3                                /* ret                 */
};

static void callrel(uint8_t *code, unsigned at, unsigned target)
{
	code[at] = 0xe8;
	put32(code, at + 1u, (uint32_t)(target - (at + 5u)));
}

int main(void)
{
	static uint8_t b[0x800], code[256];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	uint32_t i, n_net, n_opaque;
	uint64_t n;
	int saw_connect, saw_send;

	/*
	 * 1. TWO CALLERS, EACH PUSHING A CONSTANT: connect (3) and send (9).
	 *    The third call pushes nothing and has to get no node - a stack
	 *    that is only a few slots deep still holds the last thing pushed.
	 */
	memset(code, 0x90, sizeof code);
	code[0] = 0x50;  code[1] = 0x6a;  code[2] = 0x03;       /* push eax; push 3 */
	callrel(code, 3, 28);
	code[8] = 0x83;  code[9] = 0xc4;  code[10] = 0x08;      /* add esp,8        */
	code[11] = 0x50; code[12] = 0x6a; code[13] = 0x09;      /* push eax; push 9 */
	callrel(code, 14, 28);
	code[19] = 0x83; code[20] = 0xc4; code[21] = 0x08;
	callrel(code, 22, 28);                                  /* nothing pushed   */
	code[27] = 0xc3;
	memcpy(code + 28, wrapper, sizeof wrapper);
	n = elf32(b, sizeof b, code, 28u + sizeof wrapper);
	s = scan(b, n, &ctx, "two callers");
	n_net = 0;
	saw_connect = saw_send = 0;
	n_opaque = 0;
	for (i = 0; s && i < count(s); i++) {
		const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

		if (h->cap == KOF_NUCLEO_NET_CONNECT) {
			n_net++;
			saw_connect += h->at == 0x54u + 3u;     /* the call that pushed 3 */
		} else if (h->cap == KOF_NUCLEO_NET_WRITE) {
			n_net++;
			saw_send += h->at == 0x54u + 14u;       /* the call that pushed 9 */
		} else if (h->bits & KOF_DIAG_H_OPAQUE) {
			n_opaque++;
		}
		CK(h->at != 0x54u + 22u);       /* the call with no argument */
	}
	CK(n_net == 2);
	CK(saw_connect == 1);
	CK(saw_send == 1);
	CK(n_opaque == 0);      /* the site is explained, not unknown */
	kof_diag_scan_free(s);

	/*
	 * 2. NOBODY CALLS IT WITH A VALUE: the site must be REPORTED as a
	 *    socketcall of unknown kind. Dropping it again is the fault this
	 *    test exists for.
	 */
	memset(code, 0x90, sizeof code);
	callrel(code, 0, 6);                    /* call with nothing pushed */
	code[5] = 0xc3;
	memcpy(code + 6, wrapper, sizeof wrapper);
	n = elf32(b, sizeof b, code, 6u + sizeof wrapper);
	s = scan(b, n, &ctx, "no resolvable caller");
	n_opaque = 0;
	for (i = 0; s && i < count(s); i++) {
		const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

		CK(h->cap != KOF_NUCLEO_NET_CONNECT && h->cap != KOF_NUCLEO_NET_WRITE);
		if (h->bits & KOF_DIAG_H_OPAQUE)
			n_opaque++;
	}
	CK(n_opaque == 1);
	kof_diag_scan_free(s);

	/*
	 * 3. THE SUB-CALL IS KNOWN AT THE SITE: nothing is deferred, and the
	 *    node sits on the instruction as it always did.
	 */
	{
		static const uint8_t local[] = {
			0x6a, 0x03, 0x5b,             /* push 3 ; pop ebx   */
			0xb8, 0x66, 0x00, 0x00, 0x00, /* mov eax,0x66       */
			0xcd, 0x80                    /* int 0x80 - connect */
		};
		int found = 0;

		n = elf32(b, sizeof b, local, sizeof local);
		s = scan(b, n, &ctx, "resolved at the site");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			found += h->cap == KOF_NUCLEO_NET_CONNECT &&
				 h->at == 0x54u + 8u;
		}
		CK(found == 1);
		kof_diag_scan_free(s);
	}

	printf("diag wrap: the caller's constant, a call with none, the unknown site%s\n",
	       fails ? " - FAILED" : " - ok");
	return fails != 0;
}
