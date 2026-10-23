#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_pe_teb.c - the thread block a Windows loader would have installed: TEB, PEB, loader lists, heap.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and emu_unpack_private.h for what the
 * files share.
 */
#include "emu_unpack_private.h"

/* ---- the same two jobs, for a PE ------------------------------------------
 *
 * See emu_unpack.h for why a PE is worth running with no API layer behind it.
 * Everything below is the PE restatement of the ELF half above; where a
 * threshold or a rule is the same it IS the same constant, not a second copy
 * of the number that can drift from it.
 */

/*
 * ---- THE THREAD BLOCK A WINDOWS LOADER WOULD HAVE INSTALLED ---------------
 *
 * emu_unpack.h says a PE run "goes exactly as far as the arithmetic and then
 * stops", and lists what it does not reach: "anything resolving imports by
 * walking the PEB, which faults on the first read. Those need the PEB/LDR and
 * the handful of memory APIs, and that is a separate decision to make on
 * evidence this produces rather than ahead of it."
 *
 * THIS IS THAT EVIDENCE, AND IT IS THE PEB/LDR HALF THAT IT ARGUES FOR.
 *
 * Four Themida protected PEs, run with --emu only and nothing else changed:
 *
 *     vdr.exe          25,501,494 insn   fault reading 0x30
 *     kiskis.exe       22,264,259 insn   fault reading 0x30
 *     update_v101.exe  26,616,666 insn   fault
 *     telvm.exe        48,310,170 insn   stalled
 *
 * Twenty-two to forty-eight MILLION instructions of real work before any of
 * them asked for anything - so the arithmetic half of that loader is entirely
 * within reach - and then a read of gs:[0x30] against a segment base of zero,
 * which is address 0x30, which nothing maps. The fault is not a Windows API
 * call. It is the thread block, and the thread block is data.
 *
 * SO IT IS BUILT AND NOT STUBBED. A TEB, a PEB and a PEB_LDR_DATA at fixed
 * addresses, with the fields a loader reads and nothing else:
 *
 *     TEB    Self, and the pointer to the PEB
 *     PEB    BeingDebugged (zero, because this is not a debugger), the image
 *            base, and the pointer to the LDR
 *     LDR    the three module lists
 *
 * THE MODULE LISTS ARE EMPTY AND CIRCULAR, which is a deliberate choice and
 * not a shortcut deferred. A list whose head points at itself is what Windows
 * writes for a process with no modules loaded, so a walk of it terminates
 * correctly having found nothing - the guest learns "kernel32 is not here" and
 * takes whatever path it takes for that, which is a path this can watch. The
 * alternative is inventing module entries for libraries that do not exist,
 * with base addresses that map nothing, so that the first call through
 * anything found there faults somewhere harder to read than here.
 *
 * WHAT THIS DOES NOT CLAIM. It does not make a Windows API available, and a
 * stub that decodes THROUGH an API still stops at the first call. What it
 * removes is a fault that had nothing to do with an API, and it is expected to
 * move the stop rather than end it - the point of the stop reasons, as
 * emu.h puts it, is that they "are the map of what to implement next".
 */
/*
 * Where the thread block goes. Two numbers rather than one masked down, for
 * the reason KGENOME_EMU_UNP_STACK_TOP_32 above is two: a 32-bit guest computes with 32 bits,
 * and a base it cannot represent is a base it writes through by truncating.
 * Both are clear of the stack and of any image base a PE declares.
 */
#define TEB_BASE_64   0x000007fff0001000ull
#define TEB_BASE_32   0x7ffe1000ull
#define TEB_SPAN      (4ull * KGENOME_EMU_PAGE)   /* TEB, PEB, LDR, then the heap */

/* The field offsets, which differ by width and are the architecture's. */
#define TEB64_SELF    0x30u
#define TEB64_PEB     0x60u
#define PEB64_DEBUG   0x02u
#define PEB64_IMAGE   0x10u
#define PEB64_LDR     0x18u
#define LDR64_LISTS   0x10u   /* three LIST_ENTRYs, 0x10 apart */

/* Where the LDR_DATA_TABLE_ENTRY records and their names go inside the LDR
 * page, past the three list heads and clear of each other. */
#define LDR_ENTRIES_OFF 0x100u
#define LDR_NAMES_OFF   0x600u

/*
 * NT_TIB's stack bounds, and leaving them zero was not a harmless omission.
 *
 * A guest that walks its own stack reads StackLimit to know where to stop.
 * Zero says "the bottom of the address space", so the walk runs until it hits
 * an unmapped page - which is what three different stack sizes measured:
 * 256 KB, 1 MB and 4 MB each faulted at exactly the bottom of what they were
 * given, and the instruction count grew with the size. Nothing about the
 * program was unbounded; the number it was reading was.
 */
#define TEB32_STACK_BASE  0x04u
#define TEB32_STACK_LIMIT 0x08u
#define TEB64_STACK_BASE  0x08u
#define TEB64_STACK_LIMIT 0x10u

/*
 * THE FIELDS AN ANTI-DEBUG CHECK READS, and they are read as data rather than
 * asked for through an API - so an environment that answers IsDebuggerPresent
 * honestly and leaves these unset has told the truth twice and lied once.
 *
 *   NtGlobalFlag      0x70 under a debugger, 0 otherwise. The page is zeroed,
 *                     so the right answer is already there; named here so a
 *                     later reader knows it is answered rather than forgotten.
 *   ProcessHeap       a POINTER, and a null one is the worse failure: a guest
 *                     reading the heap's Flags through it faults at a low
 *                     address instead of reading a zero. It gets a real page.
 *   heap Flags        2 and ForceFlags 0 on a normal process; 0x40000062 and
 *                     0x40000060 under a debugger.
 */
#define PEB32_NTGLOBAL   0x68u
#define PEB64_NTGLOBAL   0xbcu
#define PEB32_HEAP       0x18u
#define PEB64_HEAP       0x30u
#define HEAP32_FLAGS     0x0cu
#define HEAP32_FORCE     0x10u
#define HEAP64_FLAGS     0x70u
#define HEAP64_FORCE     0x74u
#define HEAP_PAGE_OFF    (3ull * KGENOME_EMU_PAGE)   /* after TEB, PEB, LDR */

#define TEB32_SELF    0x18u
#define TEB32_PEB     0x30u
#define PEB32_DEBUG   0x02u
#define PEB32_IMAGE   0x08u
#define PEB32_LDR     0x0cu
#define LDR32_LISTS   0x0cu   /* three LIST_ENTRYs, 8 apart */

static void put_w(uint8_t *p, unsigned bits, uint64_t v)
{
	unsigned i, w = bits == 32u ? 4u : 8u;

	for (i = 0; i < w; i++)
		p[i] = (uint8_t)(v >> (8u * i));
}

int kgenome_emu_unp_build_teb_pe(struct kgenome_emu *e, unsigned bits, uint64_t image_base,
			uint64_t stack_lo, uint64_t stack_hi)
{
	uint8_t page[4u * KGENOME_EMU_PAGE];
	uint64_t teb = bits == 32u ? TEB_BASE_32 : TEB_BASE_64;
	uint64_t peb = teb + KGENOME_EMU_PAGE;
	uint64_t ldr = peb + KGENOME_EMU_PAGE;
	uint8_t *t = page, *p = page + KGENOME_EMU_PAGE, *l = page + 2u * KGENOME_EMU_PAGE;
	uint8_t *hp = page + 3u * KGENOME_EMU_PAGE;
	uint64_t heap = teb + HEAP_PAGE_OFF;
	unsigned w = bits == 32u ? 4u : 8u;
	unsigned lists = bits == 32u ? LDR32_LISTS : LDR64_LISTS;
	unsigned k;

	memset(page, 0, sizeof page);

	if (bits == 32u) {
		/*
		 * TEB+0 IS THE SEH CHAIN HEAD AND ITS EMPTY VALUE IS NOT ZERO.
		 *
		 * Windows writes 0xFFFFFFFF there - "end of chain" - and a
		 * walker tests for exactly that. A zero reads as a registration
		 * record at address zero, which is a different thing and is
		 * what a program checking whether it may install a handler sees
		 * as "something is already there".
		 */
		put_w(t + 0u, bits, 0xffffffffu);
		put_w(t + TEB32_STACK_BASE,  bits, stack_hi);
		put_w(t + TEB32_STACK_LIMIT, bits, stack_lo);
		put_w(t + TEB32_SELF, bits, teb);
		put_w(t + TEB32_PEB,  bits, peb);
		put_w(p + PEB32_HEAP, bits, heap);
		put_w(p + PEB32_NTGLOBAL, bits, 0);
		put_w(hp + HEAP32_FLAGS, bits, 2u);
		put_w(hp + HEAP32_FORCE, bits, 0);
		p[PEB32_DEBUG] = 0;
		put_w(p + PEB32_IMAGE, bits, image_base);
		put_w(p + PEB32_LDR,   bits, ldr);
	} else {
		put_w(t + TEB64_STACK_BASE,  bits, stack_hi);
		put_w(t + TEB64_STACK_LIMIT, bits, stack_lo);
		put_w(t + TEB64_SELF, bits, teb);
		put_w(t + TEB64_PEB,  bits, peb);
		put_w(p + PEB64_HEAP, bits, heap);
		put_w(p + PEB64_NTGLOBAL, bits, 0);
		put_w(hp + HEAP64_FLAGS, bits, 2u);
		put_w(hp + HEAP64_FORCE, bits, 0);
		p[PEB64_DEBUG] = 0;
		put_w(p + PEB64_IMAGE, bits, image_base);
		put_w(p + PEB64_LDR,   bits, ldr);
	}

	/*
	 * THE MODULE LIST, WITH MODULES IN IT.
	 *
	 * These three lists used to be empty - each head pointing at itself,
	 * which is a correct empty circular list and is what a walker sees when
	 * nothing is loaded. Nothing is ever loaded on Windows: a process that
	 * has reached its entry point has at least its own image, ntdll and
	 * kernel32, and code that wants kernel32 without importing it walks
	 * this list to find it rather than calling anything.
	 *
	 * Measured on an MPRESS sample: its stage-2 resolver compares module
	 * names against "NTDLL.DLL", found no entry to compare, carried on with
	 * a pointer it had not set, and ended up calling a module's MZ header.
	 * The whole run - 310701 instructions - was spent after that mistake.
	 *
	 * ORDER MATTERS AND IS NOT THIS FILE'S CHOICE. The classic sequence
	 * reads InMemoryOrderModuleList.Flink, steps once for ntdll and twice
	 * for kernel32, so those two are second and third with the image first.
	 * kgenome_emu_win_mod_base lists kernel32 first, which is the order of the
	 * function table and has nothing to do with load order.
	 */
	{
		/*
		 * EVERY MODULE, ONCE. This listed eight into an array of nine, so
		 * the ninth slot was zero - kernel32 again, appended to the list a
		 * second time - and kernelbase, which has an image of its own, was
		 * never in the list at all. ws2_32 is here from the start although
		 * Windows only lists it after LoadLibrary: a resolver walks the
		 * list, and the environment has no loader to add to it later.
		 */
		static const unsigned load_order[KGENOME_EMU_WIN_MOD_RESIDENT] = {
			KGENOME_EMU_WIN_MOD_NTDLL, KGENOME_EMU_WIN_MOD_K32,
			KGENOME_EMU_WIN_MOD_KBASE,
			KGENOME_EMU_WIN_MOD_USER32, KGENOME_EMU_WIN_MOD_ADVAPI32,
			KGENOME_EMU_WIN_MOD_SHELL32, KGENOME_EMU_WIN_MOD_SHLWAPI,
			KGENOME_EMU_WIN_MOD_MSVCRT, KGENOME_EMU_WIN_MOD_OLE32,
			KGENOME_EMU_WIN_MOD_WS2
		};
		unsigned esz  = bits == 32u ? 0x40u : 0x70u;
		unsigned dllb = bits == 32u ? 0x18u : 0x30u;
		unsigned szof = bits == 32u ? 0x20u : 0x40u;
		unsigned fulln = bits == 32u ? 0x24u : 0x48u;
		unsigned basen = bits == 32u ? 0x2cu : 0x58u;
		unsigned nptr  = bits == 32u ? 4u : 8u;   /* Buffer within it */
		uint64_t ent[KGENOME_EMU_WIN_MOD_RESIDENT + 1u];
		unsigned n_ent = 0, m, ni = LDR_NAMES_OFF;

		/* The image itself, with no name: this file does not know what
		 * it was called, and a zero-length UNICODE_STRING says that
		 * rather than inventing one. Its BASE is the true part and is
		 * what a walker taking the first entry wants. */
		ent[n_ent++] = LDR_ENTRIES_OFF;
		put_w(l + LDR_ENTRIES_OFF + dllb, bits, image_base);
		put_w(l + LDR_ENTRIES_OFF + szof, bits, 0);
		/*
		 * A NAME, BECAUSE A ZERO-LENGTH ONE IS A TRAP FOR THE WALKER THAT
		 * IS MOST LIKELY TO BE HERE. The loop that hashes a module's name
		 * is `movzx rcx,[Length] ... loop`, and `loop` with rcx == 0 does
		 * not run zero times - it wraps and runs 2^64. MEASURED on a
		 * Metasploit stager: the first entry is the program's own image,
		 * its length was zero, and the resolver spent its whole run
		 * hashing from a null buffer until it read off the end of memory,
		 * so every API the stager asked for was "not found". Windows names
		 * the image (its path); this does not know the path, so it says
		 * what it does know and nothing that a stub would take for a real
		 * module.
		 */
		{
			static const char imgname[] = "IMAGE.EXE";
			unsigned ilen = (unsigned)sizeof imgname - 1u, c;
			unsigned ioff = LDR_ENTRIES_OFF;

			for (c = 0; c < ilen; c++) {
				l[ni + 2u * c]      = (uint8_t)imgname[c];
				l[ni + 2u * c + 1u] = 0;
			}
			l[ioff + fulln] = (uint8_t)(2u * ilen);
			l[ioff + fulln + 1u] = (uint8_t)((2u * ilen) >> 8);
			l[ioff + fulln + 2u] = (uint8_t)(2u * ilen + 2u);
			l[ioff + fulln + 3u] = (uint8_t)((2u * ilen + 2u) >> 8);
			put_w(l + ioff + fulln + nptr, bits, ldr + ni);
			l[ioff + basen] = (uint8_t)(2u * ilen);
			l[ioff + basen + 1u] = (uint8_t)((2u * ilen) >> 8);
			l[ioff + basen + 2u] = (uint8_t)(2u * ilen + 2u);
			l[ioff + basen + 3u] = (uint8_t)((2u * ilen + 2u) >> 8);
			put_w(l + ioff + basen + nptr, bits, ldr + ni);
			ni += 2u * (ilen + 1u);
		}

		for (m = 0; m < KGENOME_EMU_WIN_MOD_RESIDENT; m++) {
			unsigned mi = load_order[m];
			uint64_t mb = kgenome_emu_win_mod_base(mi, bits);
			const char *nm = kgenome_emu_win_mod_name(mi);
			unsigned off = LDR_ENTRIES_OFF + n_ent * esz;
			unsigned len = (unsigned)strlen(nm), c;

			if (!mb || off + esz > LDR_NAMES_OFF)
				continue;
			if (ni + 2u * (len + 1u) > KGENOME_EMU_PAGE)
				break;
			for (c = 0; c < len; c++) {
				l[ni + 2u * c]      = (uint8_t)nm[c];
				l[ni + 2u * c + 1u] = 0;
			}
			put_w(l + off + dllb, bits, mb);
			put_w(l + off + szof, bits, KGENOME_EMU_UNP_K32_SPAN);
			/* Both names are the same buffer: this environment has a
			 * module's name and not a path, and a stub comparing
			 * either gets the truth rather than an invented one. */
			l[off + fulln] = (uint8_t)(2u * len);
			l[off + fulln + 1u] = (uint8_t)((2u * len) >> 8);
			l[off + fulln + 2u] = (uint8_t)(2u * len + 2u);
			l[off + fulln + 3u] = (uint8_t)((2u * len + 2u) >> 8);
			put_w(l + off + fulln + nptr, bits, ldr + ni);
			l[off + basen] = (uint8_t)(2u * len);
			l[off + basen + 1u] = (uint8_t)((2u * len) >> 8);
			l[off + basen + 2u] = (uint8_t)(2u * len + 2u);
			l[off + basen + 3u] = (uint8_t)((2u * len + 2u) >> 8);
			put_w(l + off + basen + nptr, bits, ldr + ni);
			ni += 2u * (len + 1u);
			ent[n_ent++] = off;
		}

		/*
		 * Three circular doubly-linked lists over the same entries. The
		 * LIST_ENTRY for list k sits at entry + k * 2 * w, and that is
		 * the address the links carry - a walker is handed a pointer to
		 * the link, not to the record, and subtracts the offset itself.
		 */
		for (k = 0; k < 3u; k++) {
			uint64_t head = ldr + lists + (uint64_t)k * 2u * w;
			uint8_t *at = l + lists + k * 2u * w;
			unsigned kl = k * 2u * w, q;

			if (!n_ent) {
				put_w(at, bits, head);
				put_w(at + w, bits, head);
				continue;
			}
			put_w(at,     bits, ldr + ent[0] + kl);
			put_w(at + w, bits, ldr + ent[n_ent - 1u] + kl);
			for (q = 0; q < n_ent; q++) {
				uint8_t *le = l + ent[q] + kl;
				uint64_t nx = q + 1u < n_ent
					    ? ldr + ent[q + 1u] + kl : head;
				uint64_t pv = q ? ldr + ent[q - 1u] + kl : head;

				put_w(le,     bits, nx);
				put_w(le + w, bits, pv);
			}
		}
		put_w(l + 0u, bits, 0x30u);     /* Length */
		l[4] = 1;                       /* Initialized */
	}

	if (!kgenome_emu_map(e, teb, page, sizeof page, TEB_SPAN,
			 KGENOME_EMU_R | KGENOME_EMU_W))
		return 0;
	/*
	 * 64-bit Windows addresses the TEB through GS and 32-bit through FS.
	 * The numbers are the decoder's segment ids, which is what the
	 * interpreter's address arithmetic uses.
	 */
	kgenome_emu_set_seg_base(e, bits == 32u ? 4u : 5u, teb);
	kgenome_emu_win_set_heap(e, heap);
	return 1;
}
