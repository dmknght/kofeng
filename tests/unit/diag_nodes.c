/*
 * diag_nodes - the nodes a real payload yields, and the links between them.
 *
 * The property under test: on the SAME bytes, the walk finds the same
 * capabilities, with the same flags, linked the same way. Not "some nodes" -
 * the right ones.
 *
 * WHY THIS SHAPE OF INPUT. Two msfvenom stagers, one per architecture, and
 * they are here together because the thing most likely to break is the part
 * where ONE diagnose covers BOTH. x86-64 links its nodes by a returned
 * pointer; i386 links them by a shared stack region, because mprotect
 * returns zero and names its region in an argument instead. A change that
 * quietly drops one of those still passes every test written against the
 * other.
 *
 * WHY A TEST AND NOT A CORPUS RUN. Four faults were found getting this far
 * and all four were SILENT - three produced fewer nodes and one produced a
 * WRONG one, and in every case the only symptom was a sample that had
 * matched yesterday no longer matching. A corpus cannot report that,
 * because it cannot say what a file was supposed to produce. Each is a case
 * below:
 *
 *   entry point       An executable segment usually starts at file offset
 *                     zero and so CONTAINS THE ELF HEADER. Reading it from
 *                     the front decodes `7f E L F ...` as instructions and
 *                     carries the desync into the real code - the mmap came
 *                     back with its number unreadable.
 *   int 0x80          i386 reaches the kernel through a software interrupt,
 *                     which the decoder classes as KDIS_INT and not
 *                     KDIS_SYSCALL. Reading only the latter found ZERO
 *                     nodes in every 32-bit payload.
 *   stale rax         A `syscall` does not WRITE rax as far as the decoder
 *                     is concerned, so the constant map keeps the number
 *                     that went IN. The exit on the failure arm left 0x3c
 *                     behind and the read two instructions later was read
 *                     as exit - wrong, not missing.
 *   unread argument   mmap is refined to ALLOC_EXEC by testing PROT_EXEC in
 *                     its third argument. Handing a zero for an argument
 *                     that could not be read says "no execute permission",
 *                     which is a claim, not a default.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofeng.h"
#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/analyzers/parsers/kofformat.h"
#include "../../libkofeng/detectors/pathogen/kofdiag.h"

static int fails;

#define CK(cond) do { \
	if (!(cond)) { \
		printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
		fails++; \
	} \
} while (0)

/*
 * linux/x64/meterpreter/reverse_tcp, wrapped in the ELF template msfvenom
 * emits: one PT_LOAD at file offset 0 covering the header, and an entry at
 * +0x78. The template is part of the test - it is what makes the first case
 * above reachable.
 */
static uint8_t x64[0xfa];
static uint8_t x86[0xd6];

static void put64(uint8_t *b, unsigned at, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[at + i] = (uint8_t)(v >> (8u * i));
}
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

static void build_x64(void)
{
	static const uint8_t code[] = {
		0x31, 0xff, 0x6a, 0x09, 0x58, 0x99, 0xb6, 0x10, 0x48, 0x89,
		0xd6, 0x4d, 0x31, 0xc9, 0x6a, 0x22, 0x41, 0x5a, 0x6a, 0x07,
		0x5a, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x51, 0x6a, 0x0a,
		0x41, 0x59, 0x50, 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f,
		0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0x3b,
		0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0x27, 0x0f, 0x7f, 0x00,
		0x00, 0x01, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a,
		0x2a, 0x58, 0x0f, 0x05, 0x59, 0x48, 0x85, 0xc0, 0x79, 0x25,
		0x49, 0xff, 0xc9, 0x74, 0x18, 0x57, 0x6a, 0x23, 0x58, 0x6a,
		0x00, 0x6a, 0x05, 0x48, 0x89, 0xe7, 0x48, 0x31, 0xf6, 0x0f,
		0x05, 0x59, 0x59, 0x5f, 0x48, 0x85, 0xc0, 0x79, 0xc7, 0x6a,
		0x3c, 0x58, 0x6a, 0x01, 0x5f, 0x0f, 0x05, 0x5e, 0x6a, 0x7e,
		0x5a, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x78, 0xed, 0xff, 0xe6
	};

	memset(x64, 0, sizeof x64);
	memcpy(x64, "\177ELF\2\1\1", 7);
	put16(x64, 16, 2);              /* ET_EXEC                 */
	put16(x64, 18, 0x3e);           /* EM_X86_64               */
	put32(x64, 20, 1);
	put64(x64, 24, 0x400078u);      /* e_entry                 */
	put64(x64, 32, 64);             /* e_phoff                 */
	put16(x64, 52, 64);             /* e_ehsize                */
	put16(x64, 54, 56);             /* e_phentsize             */
	put16(x64, 56, 1);              /* e_phnum                 */
	put32(x64, 64, 1);              /* PT_LOAD                 */
	put32(x64, 68, 7);              /* RWX                     */
	put64(x64, 72, 0);              /* p_offset - COVERS THE HEADER */
	put64(x64, 80, 0x400000u);      /* p_vaddr                 */
	put64(x64, 96, sizeof x64);     /* p_filesz                */
	put64(x64, 104, sizeof x64);    /* p_memsz                 */
	memcpy(x64 + 0x78, code, sizeof code);
}

static void build_x86(void)
{
	static const uint8_t code[] = {
		0x6a, 0x0a, 0x5e, 0x31, 0xdb, 0xf7, 0xe3, 0x53, 0x43, 0x53,
		0x6a, 0x02, 0xb0, 0x66, 0x89, 0xe1, 0xcd, 0x80, 0x97, 0x5b,
		0x68, 0xc0, 0xa8, 0x32, 0x0c, 0x68, 0x02, 0x00, 0x22, 0xb8,
		0x89, 0xe1, 0x6a, 0x66, 0x58, 0x50, 0x51, 0x57, 0x89, 0xe1,
		0x43, 0xcd, 0x80, 0x85, 0xc0, 0x79, 0x19, 0x4e, 0x74, 0x3d,
		0x68, 0xa2, 0x00, 0x00, 0x00, 0x58, 0x6a, 0x00, 0x6a, 0x05,
		0x89, 0xe3, 0x31, 0xc9, 0xcd, 0x80, 0x85, 0xc0, 0x79, 0xbd,
		0xeb, 0x27, 0xb2, 0x07, 0xb9, 0x00, 0x10, 0x00, 0x00, 0x89,
		0xe3, 0xc1, 0xeb, 0x0c, 0xc1, 0xe3, 0x0c, 0xb0, 0x7d, 0xcd,
		0x80, 0x85, 0xc0, 0x78, 0x10, 0x5b, 0x89, 0xe1, 0x99, 0xb6,
		0x0c, 0xb0, 0x03, 0xcd, 0x80, 0x85, 0xc0, 0x78, 0x02, 0xff,
		0xe1, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbb, 0x01, 0x00, 0x00,
		0x00, 0xcd, 0x80
	};

	memset(x86, 0, sizeof x86);
	memcpy(x86, "\177ELF\1\1\1", 7);
	put16(x86, 16, 2);
	put16(x86, 18, 3);              /* EM_386                  */
	put32(x86, 20, 1);
	put32(x86, 24, 0x8048054u);     /* e_entry                 */
	put32(x86, 28, 52);             /* e_phoff                 */
	put16(x86, 40, 52);             /* e_ehsize                */
	put16(x86, 42, 32);             /* e_phentsize             */
	put16(x86, 44, 1);              /* e_phnum                 */
	put32(x86, 52, 1);              /* PT_LOAD                 */
	put32(x86, 56, 0);              /* p_offset                */
	put32(x86, 60, 0x8048000u);     /* p_vaddr                 */
	put32(x86, 68, sizeof x86);     /* p_filesz                */
	put32(x86, 72, sizeof x86);     /* p_memsz                 */
	put32(x86, 76, 5);              /* RX                      */
	memcpy(x86 + 0x54, code, sizeof code);
}

/* Parse through the engine's own table, so the test exercises the path a
 * scan takes rather than a shortcut only it knows. */
static int parse(const uint8_t *b, uint64_t n, struct kof_obj_ctx *ctx,
		 void *view)
{
	const struct kof_parser *pl;
	uint32_t np, i;
	kof_buf buf;

	buf.p = b;
	buf.n = n;
	memset(ctx, 0, sizeof *ctx);
	pl = kof_parser_list(&np);
	for (i = 0; i < np; i++)
		if (pl[i].sniff && pl[i].sniff(buf) &&
		    pl[i].parse && pl[i].parse(buf, view, ctx))
			return 1;
	return 0;
}

static const struct kof_diag_hit *find(const struct kof_diag_scan *s,
				       uint16_t cap, uint32_t *idx)
{
	uint32_t i;

	for (i = 0; i < kof_diag_scan_count(s); i++) {
		const struct kof_diag_hit *h = kof_diag_scan_at(s, i);

		if (h->cap == cap) {
			if (idx)
				*idx = i;
			return h;
		}
	}
	return NULL;
}

/* Is `h` linked to node `want` in `role`, either by value or by region. */
static int has_in(const struct kof_diag_hit *h, uint16_t want, uint8_t role)
{
	uint8_t i;

	for (i = 0; h && i < h->n_in; i++)
		if (h->in[i].role == role && h->in[i].from == want)
			return 1;
	return 0;
}

static void one_arch(const uint8_t *b, uint64_t n, const char *what, int region)
{
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	const struct kof_diag_hit *a, *r, *x;
	uint32_t ia = 0;

	memset(view, 0, sizeof view);
	if (!parse(b, n, &ctx, view)) {
		printf("  FAIL %s: the engine did not parse it\n", what);
		fails++;
		return;
	}
	s = kof_diag_scan(&ctx, b, n);
	if (!s) {
		printf("  FAIL %s: no scan\n", what);
		fails++;
		return;
	}

	/*
	 * THE ALLOCATION IS EXECUTABLE AND WRITABLE, and that is the whole
	 * discriminator: a JIT asks for RW and mprotects to RX afterwards,
	 * so W AND X IN ONE CALL is what separates the two. Measured, no
	 * clean binary in 846 of /usr/bin does it.
	 */
	a = find(s, KOF_CAP_ALLOC_EXEC, &ia);
	CK(a != NULL);
	if (a) {
		CK((a->flags & KOF_FLOWF_WX) != 0);
		CK(!(a->bits & KOF_DIAG_H_ARG_UNKNOWN));
		CK(region == ((a->bits & KOF_DIAG_H_REGION_STACK) != 0));
	}

	/* The read that fills it, and the branch that runs it. Both linked
	 * to the allocation and not merely present beside it.
	 *
	 * mem-read: read(2) takes a descriptor and the walk has not been
	 * told what this one is - see KOF_CG_IO. A run that proves it came
	 * from a socket corrects the word to net-recv, and the diagnose below
	 * still matches because a rule names the level it means. */
	r = find(s, KOF_CAP_MEM_READ, NULL);
	x = find(s, KOF_CAP_EXEC_REG, NULL);
	CK(r != NULL);
	CK(x != NULL);
	if (a && r && x) {
		uint16_t src = region ? KOF_DIAG_FROM_STACK : (uint16_t)ia;

		CK(has_in(r, src, KOF_DIAG_ROLE_BUFFER));
		CK(has_in(x, src, KOF_DIAG_ROLE_TARGET));
	}

	/*
	 * AND THE DIAGNOSE OVER THEM MATCHES, with ONE tree for both
	 * architectures. It names no link kind: the value link and the
	 * region link are two ways the engine can prove the same statement,
	 * and a rule that had to pick would need two copies of itself.
	 */
	{
		static const struct kof_diag_node nd[] = {
			{ KOF_CAP_ALLOC_EXEC, KOF_FLOWF_WX, KOF_DIAG_NO_PARENT,
			  KOF_DIAG_ROLE_NONE, 0, 0 },
			{ KOF_CAP_MEM_READ, 0, 0, KOF_DIAG_ROLE_BUFFER,
			  KOF_DIAG_B_TOUCH, 0 },
			{ KOF_CAP_EXEC_REG, 0, 0, KOF_DIAG_ROLE_TARGET, 0, 0 },
		};
		static const struct kof_diag dg = {
			1, KOF_DIAG_VIA_SYSCALL, 3, "rwx_exec", nd
		};
		uint16_t bind[4];
		uint8_t nb = 0;

		CK(kof_diag_match(s, &dg, bind, &nb) == 1);
		/* One touch point was offered, so exactly one comes back -
		 * the cost of an answer is the size of the question. */
		CK(nb == 1);
	}
	kof_diag_scan_free(s);
}

/*
 * A SHAPE THAT MUST NOT MATCH: the same three capabilities with no link
 * between them.
 *
 * Without this the test would pass against a matcher that only counted
 * capabilities, which is the version this replaced - and counting is what
 * made a payload with an unrelated mmap, an unrelated read and a vtable
 * call look like a stager.
 */
static void unlinked_does_not_match(void)
{
	static const struct kof_diag_node nd[] = {
		{ KOF_CAP_ALLOC_EXEC, KOF_FLOWF_WX, KOF_DIAG_NO_PARENT,
		  KOF_DIAG_ROLE_NONE, 0, 0 },
		{ KOF_CAP_MEM_READ, 0, 0, KOF_DIAG_ROLE_BUFFER, 0, 0 },
	};
	static const struct kof_diag dg = {
		1, KOF_DIAG_VIA_SYSCALL, 2, "needs_a_link", nd
	};
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;

	/* mmap(RWX) into rax, then a read whose buffer came from NOWHERE
	 * this walk saw - a different register, never written here. */
	static const uint8_t code[] = {
		0x31, 0xff,                   /* xor edi,edi            */
		0x6a, 0x09, 0x58,             /* push 9 ; pop rax       */
		0x99, 0xb6, 0x10,             /* cdq ; mov dh,0x10      */
		0x48, 0x89, 0xd6,             /* mov rsi,rdx            */
		0x4d, 0x31, 0xc9,             /* xor r9,r9              */
		0x6a, 0x22, 0x41, 0x5a,       /* push 0x22 ; pop r10    */
		0x6a, 0x07, 0x5a,             /* push 7 ; pop rdx       */
		0x0f, 0x05,                   /* syscall  - mmap RWX    */
		0x31, 0xc0,                   /* xor eax,eax  - read    */
		0x31, 0xff,                   /* xor edi,edi            */
		0x48, 0x8b, 0x74, 0x24, 0x08, /* mov rsi,[rsp+8] - from nowhere */
		0x6a, 0x7e, 0x5a,             /* push 0x7e ; pop rdx    */
		0x0f, 0x05                    /* syscall  - read        */
	};
	uint8_t b[0x100];

	memset(b, 0, sizeof b);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2); put16(b, 18, 0x3e); put32(b, 20, 1);
	put64(b, 24, 0x400078u); put64(b, 32, 64);
	put16(b, 52, 64); put16(b, 54, 56); put16(b, 56, 1);
	put32(b, 64, 1); put32(b, 68, 7);
	put64(b, 72, 0); put64(b, 80, 0x400000u);
	put64(b, 96, sizeof b); put64(b, 104, sizeof b);
	memcpy(b + 0x78, code, sizeof code);

	memset(view, 0, sizeof view);
	if (!parse(b, sizeof b, &ctx, view)) {
		printf("  FAIL unlinked: the engine did not parse it\n");
		fails++;
		return;
	}
	s = kof_diag_scan(&ctx, b, sizeof b);
	CK(s != NULL);
	if (!s)
		return;
	/* Both capabilities are there... */
	CK(find(s, KOF_CAP_ALLOC_EXEC, NULL) != NULL);
	CK(find(s, KOF_CAP_MEM_READ, NULL) != NULL);
	/* ...and the diagnose still must not match, because nothing joins
	 * them. */
	CK(kof_diag_match(s, &dg, NULL, NULL) == 0);
	kof_diag_scan_free(s);
}

/*
 * AN UNREADABLE prot IS NOT A prot OF ZERO.
 *
 * mmap is refined to ALLOC_EXEC by testing PROT_EXEC in its third
 * argument. When the walk could not read that argument, handing the
 * refinement a zero makes it answer "no execute permission" - a claim,
 * where silence was the only honest answer. The node must say it does not
 * know, and a diagnose demanding an executable allocation must then not
 * match it.
 *
 * WRITTEN AS ITS OWN CASE because the two stagers above both resolve their
 * prot, so neither of them reaches this line - removing the flag entirely
 * left every assertion in this file passing, which is how this case came
 * to be written.
 */
static void unreadable_prot_is_not_zero(void)
{
	static const struct kof_diag_node nd[] = {
		{ KOF_CAP_ALLOC_EXEC, KOF_FLOWF_WX, KOF_DIAG_NO_PARENT,
		  KOF_DIAG_ROLE_NONE, 0, 0 },
	};
	static const struct kof_diag dg = {
		1, KOF_DIAG_VIA_SYSCALL, 1, "needs_wx", nd
	};
	/* mmap with prot loaded from memory - a value this does not follow. */
	static const uint8_t code[] = {
		0x31, 0xff,                   /* xor edi,edi             */
		0x6a, 0x09, 0x58,             /* push 9 ; pop rax        */
		0x99, 0xb6, 0x10,             /* cdq ; mov dh,0x10       */
		0x48, 0x89, 0xd6,             /* mov rsi,rdx             */
		0x4d, 0x31, 0xc9,             /* xor r9,r9               */
		0x6a, 0x22, 0x41, 0x5a,       /* push 0x22 ; pop r10     */
		0x48, 0x8b, 0x14, 0x24,       /* mov rdx,[rsp] - UNREAD  */
		0x0f, 0x05                    /* syscall                 */
	};
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	const struct kof_diag_hit *h;
	uint8_t b[0x100];

	memset(b, 0, sizeof b);
	memcpy(b, "\177ELF\2\1\1", 7);
	put16(b, 16, 2); put16(b, 18, 0x3e); put32(b, 20, 1);
	put64(b, 24, 0x400078u); put64(b, 32, 64);
	put16(b, 52, 64); put16(b, 54, 56); put16(b, 56, 1);
	put32(b, 64, 1); put32(b, 68, 7);
	put64(b, 72, 0); put64(b, 80, 0x400000u);
	put64(b, 96, sizeof b); put64(b, 104, sizeof b);
	memcpy(b + 0x78, code, sizeof code);

	memset(view, 0, sizeof view);
	if (!parse(b, sizeof b, &ctx, view)) {
		printf("  FAIL unreadable prot: the engine did not parse it\n");
		fails++;
		return;
	}
	s = kof_diag_scan(&ctx, b, sizeof b);
	CK(s != NULL);
	if (!s)
		return;
	/* The node is there - dropping it would lose the site entirely. */
	h = find(s, KOF_CAP_ALLOC, NULL);
	CK(h != NULL);
	/* ...and it says the argument that decides its meaning was unread. */
	CK(h && (h->bits & KOF_DIAG_H_ARG_UNKNOWN));
	/* It is NOT reported as an executable allocation... */
	CK(find(s, KOF_CAP_ALLOC_EXEC, NULL) == NULL);
	/* ...and a diagnose that demands one does not match it. */
	CK(kof_diag_match(s, &dg, NULL, NULL) == 0);
	kof_diag_scan_free(s);
}


/*
 * THE WALK DOES NOT SWEEP THE SEGMENT ANY MORE, AND THIS IS WHAT THAT COSTS
 * AND WHAT IT MUST NOT.
 *
 * sweep_region used to decode every byte of every executable segment. On a
 * frozen copy of /usr/bin - 954 files, 424 MB - that was 5.86 s on top of a
 * 1.83 s scan. It now decodes a window around each position where the three
 * syscall encodings APPEAR AS BYTES, which is 1491 positions in 182.5 MB.
 *
 * Two things can go wrong with that and both are silent:
 *
 *   FAR FROM THE START   The old walk began at the entry point and ran to
 *                        the end of the segment, so code at any depth was
 *                        reached eventually. A window has to be opened AT
 *                        the code, and a bug in choosing where leaves a
 *                        payload deep in a large segment unanalysed.
 *   A FALSE CANDIDATE    `0f 05` in data is not a syscall. The window
 *                        opened on it decodes rubbish; that must cost a
 *                        decode and nothing else - in particular it must
 *                        not consume the real code's window, which it
 *                        would if the bookkeeping that stops the walk
 *                        redoing work ran past it.
 *
 * So: the same stager, put 0x2000 bytes into a 0x4000-byte segment, with a
 * `0f 05` sitting in the filler ahead of it.
 */
static void deep_in_a_big_segment(void)
{
	static uint8_t b[0x4100];
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	const struct kof_diag_hit *a, *r, *x;
	uint32_t ia = 0;
	unsigned i;

	build_x64();
	memset(b, 0, sizeof b);
	memcpy(b, x64, 0x78);                 /* the same ELF template   */
	put64(b, 24, 0x400000u + 0x2000u);    /* e_entry - at the code   */
	put64(b, 96, sizeof b);
	put64(b, 104, sizeof b);

	/* Filler that is not instructions, with one false candidate in it. */
	for (i = 0x78; i < 0x2000u; i++)
		b[i] = (uint8_t)(i * 7u);
	b[0x1000] = 0x0f;
	b[0x1001] = 0x05;

	memcpy(b + 0x2000, x64 + 0x78, 0xfa - 0x78);

	memset(view, 0, sizeof view);
	if (!parse(b, sizeof b, &ctx, view)) {
		printf("  FAIL deep: the engine did not parse it\n");
		fails++;
		return;
	}
	s = kof_diag_scan(&ctx, b, sizeof b);
	CK(s != NULL);
	if (!s)
		return;
	a = find(s, KOF_CAP_ALLOC_EXEC, &ia);
	r = find(s, KOF_CAP_MEM_READ, NULL);
	x = find(s, KOF_CAP_EXEC_REG, NULL);
	CK(a != NULL);
	CK(r != NULL);
	CK(x != NULL);
	/* And still LINKED - a window that opened in the right place but
	 * too late carries no argument registers, so the nodes would be
	 * there and the tree would not. */
	CK(has_in(r, (uint16_t)ia, KOF_DIAG_ROLE_BUFFER));
	CK(has_in(x, (uint16_t)ia, KOF_DIAG_ROLE_TARGET));
	kof_diag_scan_free(s);
}


/*
 * EACH ANALYSIS ROUTINE CAN BE TURNED OFF ON ITS OWN.
 *
 * Not a style property. Three routines are going to share this walk - sweep
 * for syscalls, read the imports, run the gaps - and the only way to measure
 * one is to compare the walk with it against the walk without it. A routine
 * that cannot be switched off has nothing to be compared against, and a
 * regression in it is indistinguishable from a regression anywhere else.
 *
 * So: asking for everything and asking for the one routine that exists must
 * give the SAME nodes, asking for none must give none without failing, and
 * `ran` must report what actually ran rather than what was requested - a
 * routine that is named but not written yet is not a routine that ran.
 */
static void scenarios_are_separable(void)
{
	static unsigned char view[1u << 20];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *all, *one, *none;
	uint32_t n_all, n_one;

	build_x64();
	memset(view, 0, sizeof view);
	if (!parse(x64, sizeof x64, &ctx, view)) {
		printf("  FAIL scenarios: the engine did not parse it\n");
		fails++;
		return;
	}

	all  = kof_diag_scan(&ctx, x64, sizeof x64);
	one  = kof_diag_scan_with(&ctx, x64, sizeof x64,
				  KOF_DIAG_RUN_SYSCALL);
	none = kof_diag_scan_with(&ctx, x64, sizeof x64, 0u);

	CK(all != NULL);
	CK(one != NULL);
	CK(none != NULL);
	if (!all || !one || !none)
		goto out;

	n_all = kof_diag_scan_count(all);
	n_one = kof_diag_scan_count(one);
	/* The stager is found by the syscall routine, so the two must agree
	 * exactly - if they differ, something else is contributing nodes
	 * under a bit nobody asked about. */
	CK(n_all == n_one);
	CK(n_all > 0u);
	/* And nothing at all when nothing is asked for. An empty scan is a
	 * valid answer and must not be a crash or a NULL. */
	CK(kof_diag_scan_count(none) == 0u);

	/*
	 * `ran` is what HAPPENED, which is not what was asked for. The two
	 * static routines are in KOF_DIAG_RUN_DEFAULT and both run, even
	 * though the symbol routine finds nothing in a payload with no
	 * imports - running and finding nothing is a different answer from
	 * not running, and that difference is the whole reason for this
	 * field. EMULATE is not in the default set, so it must not appear.
	 */
	CK((kof_diag_scan_ran(all) & KOF_DIAG_RUN_SYSCALL) != 0u);
	CK((kof_diag_scan_ran(all) & KOF_DIAG_RUN_SYMBOL) != 0u);
	CK((kof_diag_scan_ran(all) & KOF_DIAG_RUN_EMULATE) == 0u);
	CK(kof_diag_scan_ran(none) == 0u);
out:
	kof_diag_scan_free(all);
	kof_diag_scan_free(one);
	kof_diag_scan_free(none);
}

int main(void)
{
	build_x64();
	build_x86();

	/* x86-64 links by the pointer mmap returns; i386 by the stack region
	 * mprotect names, because mprotect returns zero. */
	one_arch(x64, sizeof x64, "x86-64", 0);
	one_arch(x86, sizeof x86, "i386", 1);
	unlinked_does_not_match();
	unreadable_prot_is_not_zero();
	deep_in_a_big_segment();
	scenarios_are_separable();

	printf("diagnose nodes: entry point, int 0x80, stale rax, unread "
	       "argument, value and region links, one tree for two "
	       "architectures, a payload deep in a big segment, one\n"
	       "analysis routine at a time%s\n", fails ? "" : " - ok");
	return fails != 0;
}
