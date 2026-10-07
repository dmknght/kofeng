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

static void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}

/* An x86-64 ELF with one RWX PT_LOAD from offset zero, entry at +0x78. */
static uint64_t elf64(uint8_t *b, uint64_t cap, const uint8_t *code, uint64_t n)
{
	memset(b, 0, (size_t)cap);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2);
	put16(b, 18, 0x3e);
	put32(b, 20, 1);
	put64(b, 24, 0x400078u);
	put64(b, 32, 64);
	put16(b, 52, 64);
	put16(b, 54, 56);
	put16(b, 56, 1);
	put32(b, 64, 1);
	put32(b, 68, 7);
	put64(b, 80, 0x400000u);
	put64(b, 96, 0x78u + n);
	put64(b, 104, 0x78u + n);
	memcpy(b + 0x78, code, (size_t)n);
	return 0x78u + n;
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

	/*
	 * 4. A STUB THAT ONLY JUMPS. musl keeps one generic syscall function and
	 *    gives each cancellable wrapper a stub, `jmp generic`, so the function
	 *    that holds the syscall is reached by a jump and never by a call, and
	 *    the jump goes BACKWARD. Without the stub being read as a way in, the
	 *    syscall belonged to no function and every send of an x86-64 bot was
	 *    lost. The node must sit on the call that pushed 3.
	 */
	{
		int found = 0, bad = 0;

		memset(code, 0x90, sizeof code);
		memcpy(code, wrapper, sizeof wrapper);              /* 0..28 */
		code[29] = 0xe9;                                    /* jmp wrapper */
		put32(code, 30, (uint32_t)(0u - 34u));
		code[34] = 0x6a; code[35] = 0x03;                   /* push 3 */
		callrel(code, 36, 29);                              /* call the stub */
		code[41] = 0x83; code[42] = 0xc4; code[43] = 0x04;
		code[44] = 0xc3;
		n = elf32(b, sizeof b, code, 45);
		s = scan(b, n, &ctx, "jump stub");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			found += h->cap == KOF_NUCLEO_NET_CONNECT && h->at == 0x54u + 36u;
			bad += h->at != 0x54u + 36u && h->cap == KOF_NUCLEO_NET_CONNECT;
		}
		CK(found == 1);
		CK(bad == 0);
		kof_diag_scan_free(s);
	}

	/*
	 * 5. A PARAMETER READ THROUGH A POINTER INTO THE FRAME, the way a variadic
	 *    function fetches its third argument: lea eax,[esp]; add eax,4;
	 *    mov ebx,[eax]. A register that holds a stack address names a slot like
	 *    esp does; if it does not, the sub-call is unknown and the site stays
	 *    opaque.
	 */
	{
		static const uint8_t viaptr[] = {
			0x8d, 0x04, 0x24,             /* lea eax,[esp]      */
			0x83, 0xc0, 0x04,             /* add eax,4          */
			0x8b, 0x18,                   /* mov ebx,[eax]      */
			0xb8, 0x66, 0x00, 0x00, 0x00, /* mov eax,0x66       */
			0xcd, 0x80,                   /* int 0x80           */
			0xc3
		};
		int found = 0;

		memset(code, 0x90, sizeof code);
		code[0] = 0x6a; code[1] = 0x03;                     /* push 3 */
		callrel(code, 2, 16);
		code[7] = 0x83; code[8] = 0xc4; code[9] = 0x04;
		code[10] = 0xc3;
		memcpy(code + 16, viaptr, sizeof viaptr);
		n = elf32(b, sizeof b, code, 16u + sizeof viaptr);
		s = scan(b, n, &ctx, "parameter through a stack pointer");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			found += h->cap == KOF_NUCLEO_NET_CONNECT && h->at == 0x54u + 2u;
		}
		CK(found == 1);
		kof_diag_scan_free(s);
	}

	/*
	 * 6. A CALL TO SOMETHING THAT IS NOT A WRAPPER IN THE MIDDLE OF ONE:
	 *    uClibc's fcntl brackets its real call with pthread_setcancelstate.
	 *    That call clobbers the scratch registers and leaves the frame alone, so
	 *    the walk goes on past it.
	 */
	{
		static const uint8_t bracketed[] = {
			0x53,                         /* push ebx            */
			0xe8, 0x0f, 0x00, 0x00, 0x00, /* call helper (+15)   */
			0x8b, 0x5c, 0x24, 0x08,       /* mov ebx,[esp+8]     */
			0xb8, 0x66, 0x00, 0x00, 0x00, /* mov eax,0x66        */
			0xcd, 0x80,                   /* int 0x80            */
			0x5b,                         /* pop ebx             */
			0xc3,                         /* ret                 */
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
			0xc3                          /* helper: ret         */
		};
		int found = 0;

		memset(code, 0x90, sizeof code);
		code[0] = 0x6a; code[1] = 0x03;
		callrel(code, 2, 16);
		code[7] = 0x83; code[8] = 0xc4; code[9] = 0x04;
		code[10] = 0xc3;
		memcpy(code + 16, bracketed, sizeof bracketed);
		n = elf32(b, sizeof b, code, 16u + sizeof bracketed);
		s = scan(b, n, &ctx, "bracketed by another call");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			found += h->cap == KOF_NUCLEO_NET_CONNECT && h->at == 0x54u + 2u;
		}
		CK(found == 1);
		kof_diag_scan_free(s);
	}

	/*
	 * 7. THE NUMBER AND THE ARGUMENT IN REGISTERS. An i386 libc is free to pass
	 *    what it likes to its own helper; musl's takes the number in eax and
	 *    the first argument in edx. The wrapper moves edx to ebx and enters the
	 *    kernel, and the call that loads 0x66 and 3 must get the connect node.
	 */
	{
		static const uint8_t regs[] = {
			0x89, 0xd3,                   /* mov ebx,edx        */
			0xcd, 0x80,                   /* int 0x80           */
			0xc3
		};
		int found = 0;

		/* The helper comes FIRST, so the linear walk meets it with nothing
		 * left in eax by a caller above it - which is how a real libc lays
		 * out a helper that sits before the code that uses it. */
		memset(code, 0x90, sizeof code);
		memcpy(code, regs, sizeof regs);
		code[8] = 0xb8; put32(code, 9, 0x66);               /* mov eax,0x66 */
		code[13] = 0xba; put32(code, 14, 3);                /* mov edx,3    */
		callrel(code, 18, 0);
		code[23] = 0xc3;
		n = elf32(b, sizeof b, code, 24);
		s = scan(b, n, &ctx, "arguments in registers");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			found += h->cap == KOF_NUCLEO_NET_CONNECT && h->at == 0x54u + 18u;
		}
		CK(found == 1);
		kof_diag_scan_free(s);
	}

	/*
	 * 8. TWO PATHS THAT DO DIFFERENT THINGS TO THE STACK. musl's i386 syscall
	 *    helper branches on whether a fast entry exists: one path pushes and
	 *    returns, the other loads its parameters and enters the kernel. The
	 *    path that enters has to be evaluated with the stack as it was at the
	 *    branch, not as the other path left it; evaluated on the table's own
	 *    entry, the number came out unknown and 31 x86 files lost every
	 *    socket node.
	 */
	{
		static const uint8_t twopath[] = {
			0x85, 0xc0,                   /* test eax,eax        */
			0x74, 0x02,                   /* je +2               */
			0x50,                         /* push eax            */
			0xc3,                         /* ret                 */
			0x8b, 0x44, 0x24, 0x04,       /* mov eax,[esp+4]     */
			0x8b, 0x5c, 0x24, 0x08,       /* mov ebx,[esp+8]     */
			0xcd, 0x80,                   /* int 0x80            */
			0xc3
		};
		int found = 0;

		memset(code, 0x90, sizeof code);
		memcpy(code, twopath, sizeof twopath);              /* 0..16 */
		code[20] = 0x6a; code[21] = 0x03;                   /* push 3    */
		code[22] = 0x6a; code[23] = 0x66;                   /* push 0x66 */
		callrel(code, 24, 0);
		code[29] = 0x83; code[30] = 0xc4; code[31] = 0x08;
		code[32] = 0xc3;
		n = elf32(b, sizeof b, code, 33);
		s = scan(b, n, &ctx, "two paths");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			found += h->cap == KOF_NUCLEO_NET_CONNECT && h->at == 0x54u + 24u;
		}
		CK(found == 1);
		kof_diag_scan_free(s);
	}

	/*
	 * 9. A HELPER THAT HANDS BACK WHAT IT MADE. Mirai opens its raw sockets in
	 *    a helper and sends on the result somewhere else, so the descriptor a
	 *    send names was produced in another function. The read after the call
	 *    has to be linked to the open INSIDE the helper; a helper with no
	 *    parameters is not a wrapper, so nothing else carries the descriptor out.
	 */
	{
		static const uint8_t gen[] = {
			0x8b, 0x44, 0x24, 0x04,       /* mov eax,[esp+4]    */
			0x8b, 0x5c, 0x24, 0x08,       /* mov ebx,[esp+8]    */
			0xcd, 0x80,                   /* int 0x80           */
			0xc3
		};
		const struct kof_diag_hit *rd = NULL;
		int opened = -1;

		memset(code, 0x90, sizeof code);
		memcpy(code, gen, sizeof gen);                      /* W at 0      */
		code[12] = 0x6a; code[13] = 0x00;                   /* F: push 0   */
		code[14] = 0x6a; code[15] = 0x05;                   /*    push 5   */
		callrel(code, 16, 0);                               /*    call W   */
		code[21] = 0x83; code[22] = 0xc4; code[23] = 0x08;
		code[24] = 0xc3;
		callrel(code, 32, 12);                              /* C: call F   */
		code[37] = 0x50;                                    /*    push eax */
		code[38] = 0x6a; code[39] = 0x03;                   /*    push 3   */
		callrel(code, 40, 0);                               /*    call W   */
		code[45] = 0x83; code[46] = 0xc4; code[47] = 0x08;
		code[48] = 0xc3;
		n = elf32(b, sizeof b, code, 49);
		s = scan(b, n, &ctx, "returned descriptor");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			if (h->cap == KOF_NUCLEO_FILE_OPEN && h->at == 0x54u + 16u &&
			    !(h->bits & KOF_DIAG_H_SUPERSEDED))
				opened = (int)i;
			if (h->cap == KOF_NUCLEO_MEM_READ && h->at == 0x54u + 40u)
				rd = h;
		}
		CK(opened >= 0);
		CK(rd != NULL);
		{
			int linked = 0;
			unsigned k;

			for (k = 0; rd && k < rd->n_in; k++)
				linked += opened >= 0 && rd->in[k].from == (uint16_t)opened;
			CK(linked >= 1);
		}
		kof_diag_scan_free(s);
	}

	/*
	 * 10. A SOCKET MADE NON-BLOCKING BY ITS TYPE. socket(AF_INET,
	 *     SOCK_STREAM|SOCK_NONBLOCK, 0) is the same statement as an fcntl
	 *     afterwards, and a program that writes it this way has no fcntl for
	 *     anything to see. The call makes the open and a second node, linked.
	 *     The same call without the flag makes only the open.
	 */
	{
		static const uint8_t with[] = {
			0xbf, 0x02, 0x00, 0x00, 0x00, /* mov edi,2             */
			0xbe, 0x01, 0x08, 0x00, 0x00, /* mov esi,0x801         */
			0x31, 0xd2,                   /* xor edx,edx           */
			0xb8, 0x29, 0x00, 0x00, 0x00, /* mov eax,41 (socket)   */
			0x0f, 0x05                    /* syscall               */
		};
		uint8_t without[sizeof with];
		int nb = 0, open = -1, linked = 0;

		n = elf64(b, sizeof b, with, sizeof with);
		s = scan(b, n, &ctx, "socket with SOCK_NONBLOCK");
		for (i = 0; s && i < count(s); i++) {
			const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

			if (h->cap == KOF_NUCLEO_NET_OPEN)
				open = (int)i;
			if (h->cap == KOF_NUCLEO_FD_NONBLOCK) {
				unsigned k;

				nb++;
				for (k = 0; k < h->n_in; k++)
					linked += open >= 0 && h->in[k].from == (uint16_t)open;
			}
		}
		CK(open >= 0);
		CK(nb == 1);
		CK(linked == 1);
		kof_diag_scan_free(s);

		memcpy(without, with, sizeof with);
		without[7] = 0x00;                      /* type 1: no flag */
		n = elf64(b, sizeof b, without, sizeof without);
		s = scan(b, n, &ctx, "socket without it");
		nb = 0;
		for (i = 0; s && i < count(s); i++)
			nb += kof_diag_scan_at(s, i)->cap == KOF_NUCLEO_FD_NONBLOCK;
		CK(nb == 0);
		kof_diag_scan_free(s);
	}

	printf("diag wrap: the caller's constant, a call with none, the unknown site, a jump stub, a stack pointer, a bracketing call, register parameters, two paths, a returned descriptor, a non-blocking socket type%s\n",
	       fails ? " - FAILED" : " - ok");
	return fails != 0;
}
