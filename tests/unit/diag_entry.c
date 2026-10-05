/*
 * diag_entry - what counts as a way into the kernel, and whose vocabulary
 * names it.
 *
 * TWO FAULTS, BOTH SILENT, BOTH FOUND BY SURVEYING PE SAMPLES RATHER THAN BY
 * ANYTHING FAILING:
 *
 *   THE WRONG TABLE   kof_flow_cap_of_syscall only knows Linux. Handed a
 *                     Windows service number it does not refuse - it
 *                     ANSWERS. A Hell's Gate shaped stub, `mov r10,rcx; mov
 *                     eax,0x3b; syscall`, in a PE came back as proc-start,
 *                     because 0x3b is execve on Linux x86-64. Nothing about
 *                     that program starts a process. That is invented
 *                     information, which is worse than none: a rule written
 *                     against proc-start would fire on it.
 *
 *   THE WRONG MODE    `0f 05` is a 64-bit instruction and `cd 80` is Linux's
 *                     i386 entry. Accepting either on any object accepted
 *                     bytes that cannot execute - measured on 300 PE
 *                     samples, where this test alone took the node count
 *                     from 1539 to 389, all of the difference being
 *                     coincidental bytes inside packed sections.
 *
 * WHY A TEST AND NOT A CORPUS RUN. Both faults produce a plausible number of
 * plausible-looking nodes. A corpus says how many; it cannot say which of
 * them should not be there.
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

/*
 * A MINIMAL PE WITH ONE EXECUTABLE SECTION. Hand-built rather than taken
 * from a sample: the point is a file whose ONLY code is the stub under test,
 * so a node that appears came from it and from nothing else.
 */
static uint64_t pe(uint8_t *b, uint64_t cap, int bits64,
		   const uint8_t *code, uint64_t n)
{
	const unsigned hdr = 0x400, fa = 0x200, o = 0x80 + 24;
	const unsigned sec = o + 0xf0;

	memset(b, 0, (size_t)cap);
	b[0] = 'M'; b[1] = 'Z';
	put32(b, 0x3c, 0x80);
	memcpy(b + 0x80, "PE\0\0", 4);
	put16(b, 0x84, bits64 ? 0x8664u : 0x014cu);   /* Machine          */
	put16(b, 0x86, 1);                            /* NumberOfSections */
	put16(b, 0x94, 0xf0);                         /* SizeOfOptionalHdr */
	put16(b, 0x96, 0x22);
	put16(b, o, bits64 ? 0x20bu : 0x10bu);
	b[o + 2] = 14;
	put32(b, o + 4, (uint32_t)n);                 /* SizeOfCode        */
	put32(b, o + 16, 0x1000);                     /* EntryPoint        */
	put32(b, o + 20, 0x1000);                     /* BaseOfCode        */
	if (bits64) {
		put64(b, o + 24, 0x140000000ull);
		put32(b, o + 32, 0x1000);
		put32(b, o + 36, fa);
		put16(b, o + 40, 6);
		put16(b, o + 48, 6);
		put32(b, o + 56, 0x2000);
		put32(b, o + 60, hdr);
		put16(b, o + 68, 3);
		put32(b, o + 108, 16);
	} else {
		put32(b, o + 24, 0x1000);             /* BaseOfData        */
		put32(b, o + 28, 0x400000);           /* ImageBase         */
		put32(b, o + 32, 0x1000);
		put32(b, o + 36, fa);
		put16(b, o + 40, 6);
		put16(b, o + 48, 6);
		put32(b, o + 56, 0x2000);
		put32(b, o + 60, hdr);
		put16(b, o + 68, 3);
		put32(b, o + 92, 16);
	}
	memcpy(b + sec, ".text\0\0\0", 8);
	put32(b, sec + 8, 0x1000);                    /* VirtualSize       */
	put32(b, sec + 12, 0x1000);                   /* VirtualAddress    */
	put32(b, sec + 16, fa);                       /* SizeOfRawData     */
	put32(b, sec + 20, hdr);                      /* PointerToRawData  */
	put32(b, sec + 36, 0x60000020u);              /* CODE|EXEC|READ    */
	memcpy(b + hdr, code, (size_t)n);
	return hdr + fa;
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
						  KOF_DIAG_RUN_SYSCALL, NULL, 0u);
	printf("  FAIL %s: the engine did not parse it\n", what);
	fails++;
	return NULL;
}

static uint32_t count(struct kof_diag_scan *s)
{
	return s ? kof_diag_scan_count(s) : 0;
}

int main(void)
{
	static uint8_t b[0x800];
	struct kof_obj_ctx ctx;
	struct kof_diag_scan *s;
	uint64_t n;

	/*
	 * 1. THE CASE THAT MUST STILL WORK, so the three refusals below are
	 *    refusals and not a walk that stopped working. i386 ELF, write
	 *    through int 0x80 - msfvenom's whole 32-bit range is this shape.
	 */
	{
		static const uint8_t ok32[] = {
			0x6a, 0x01, 0x5b,             /* push 1 ; pop ebx   */
			0x6a, 0x05, 0x5a,             /* push 5 ; pop edx   */
			0x89, 0xe1,                   /* mov ecx,esp        */
			0x6a, 0x04, 0x58,             /* push 4 ; pop eax   */
			0xcd, 0x80                    /* int 0x80  - write  */
		};

		n = elf32(b, sizeof b, ok32, sizeof ok32);
		s = scan(b, n, &ctx, "i386 ELF int 0x80");
		CK(count(s) == 1u);
		if (s && count(s) == 1u)
			/* mem-write, not file-write: write(2) takes a
			 * descriptor and nothing here says what it is. See
			 * KOF_CG_IO. */
			CK(kof_diag_scan_at(s, 0)->cap == KOF_CAP_MEM_WRITE);
		kof_diag_scan_free(s);
	}

	/*
	 * 2. `0f 05` IN A 32-BIT IMAGE IS NOT A WAY INTO THE KERNEL. syscall
	 *    is a 64-bit mode instruction; the decoder will happily produce it
	 *    from these bytes in 32-bit mode, and the walk used to take it.
	 */
	{
		static const uint8_t bad32[] = {
			0x6a, 0x04, 0x58,             /* push 4 ; pop eax   */
			0x0f, 0x05                    /* syscall - cannot run */
		};

		n = elf32(b, sizeof b, bad32, sizeof bad32);
		s = scan(b, n, &ctx, "i386 ELF syscall");
		CK(count(s) == 0u);
		kof_diag_scan_free(s);
	}

	/*
	 * 3. `cd 80` IN A PE IS AN INTERRUPT WINDOWS DOES NOT SERVE. The
	 *    vector is Linux's and nobody else's, so these bytes in a PE are
	 *    data that happened to decode.
	 */
	{
		static const uint8_t int80[] = {
			0x6a, 0x04, 0x58,
			0xcd, 0x80
		};

		n = pe(b, sizeof b, 0, int80, sizeof int80);
		s = scan(b, n, &ctx, "PE int 0x80");
		CK(count(s) == 0u);
		kof_diag_scan_free(s);
	}

	/*
	 * 4. THE ONE THAT INVENTED AN ANSWER. A 64-bit PE doing a direct
	 *    system call: the node must exist, because reaching the kernel
	 *    without ntdll is the whole point of the technique - and it must
	 *    NOT be named, because 0x3b is a Windows service number here and
	 *    `execve` only on Linux.
	 */
	{
		static const uint8_t hg[] = {
			0x4c, 0x8b, 0xd1,             /* mov r10,rcx        */
			0xb8, 0x3b, 0x00, 0x00, 0x00, /* mov eax,0x3b       */
			0x0f, 0x05,                   /* syscall            */
			0xc3
		};
		const struct kof_diag_hit *h;

		n = pe(b, sizeof b, 1, hg, sizeof hg);
		s = scan(b, n, &ctx, "PE direct syscall");
		CK(count(s) == 1u);
		if (s && count(s) == 1u) {
			h = kof_diag_scan_at(s, 0);
			/* Not proc-start. Not anything. */
			CK(h->cap == KOF_CAP_NONE);
			/* And said to be a read number rather than an
			 * unreadable one - the two are different states and
			 * only one of them is interesting. */
			CK((h->bits & KOF_DIAG_H_RAW_SYSCALL) != 0);
			CK((h->bits & KOF_DIAG_H_OPAQUE) == 0);
		}
		kof_diag_scan_free(s);
	}

	/*
	 * 5. AND THE SAME PE WITH THE NUMBER OUT OF REACH. Still a node,
	 *    because the instruction is there; OPAQUE and not RAW, because
	 *    this is what a stray `0f 05` in a packed section looks like and
	 *    the two must not report the same.
	 */
	{
		static const uint8_t blind[] = {
			0x48, 0x8b, 0x04, 0x24,       /* mov rax,[rsp]      */
			0x0f, 0x05,                   /* syscall            */
			0xc3
		};
		const struct kof_diag_hit *h;

		n = pe(b, sizeof b, 1, blind, sizeof blind);
		s = scan(b, n, &ctx, "PE syscall, number unknown");
		CK(count(s) == 1u);
		if (s && count(s) == 1u) {
			h = kof_diag_scan_at(s, 0);
			CK((h->bits & KOF_DIAG_H_OPAQUE) != 0);
			CK((h->bits & KOF_DIAG_H_RAW_SYSCALL) == 0);
		}
		kof_diag_scan_free(s);
	}

	printf("diagnose kernel entry: mode, format, and whose syscall table%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
