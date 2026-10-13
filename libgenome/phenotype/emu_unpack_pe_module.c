#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_pe_module.c - the module images of a PE run: kernel32 as a stub with exports, the import table bound to it, the stack.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and emu_unpack_private.h for what the
 * files share.
 */
#include "emu_unpack_private.h"

/*
 * ---- THE kernel32 A WINDOWS STUB GOES LOOKING FOR -------------------------
 *
 * WHY AN IMAGE AND NOT A TABLE OF POINTERS.
 *
 * The four protected PEs measured above import exactly one function between
 * them - kernel32!GetModuleHandleA - which is a protector saying "give me the
 * base and I will find the rest myself". Filling that one import thunk answers
 * the first call and nothing after it: what the loader does with the base is
 * walk the export directory at it, by name.
 *
 * So this builds an image with a real export directory: a PE header, an
 * IMAGE_EXPORT_DIRECTORY, the three parallel arrays, the name strings, and a
 * page of stubs for the addresses to point at. A resolver that walks it by
 * hand - which is the only kind that reaches here - finds exactly what it
 * would find in the real thing, for the functions this environment has.
 *
 * THE NAMES ARE SORTED, because some resolvers binary search AddressOfNames
 * and the format requires it. A linear walker does not care and a binary
 * search on an unsorted table silently misses names that are there.
 *
 * WHAT A STUB IS. Eight or ten bytes: load a trap number into eax and trap.
 * emu_interp.c recognises the number and does the work - see the Windows
 * environment there, which owns the names, the numbers and the argument
 * counts so that this file and that one cannot disagree about them.
 *
 *     amd64    b8 <id32>  0f 05        c3            load, syscall, return
 *     i386     b8 <id32>  cd 80        c2 <n*4> 00   load, int 0x80, return n
 *
 * The i386 form ends in `ret n` because Windows on i386 makes the CALLEE pop
 * the arguments. Getting that wrong does not fault - it leaves the stack one
 * argument deeper on every call, and the guest fails much later somewhere that
 * says nothing about why.
 */
/*
 * THE EXPORT DIRECTORY LIVES IN A SECTION, which is not decoration.
 *
 * It was at rva 0x200 - inside the headers, below SizeOfHeaders, and covered
 * by no section header. In a loaded image an RVA is an offset so a naive
 * walker still finds it, and a careful one does not: a resolver that converts
 * the directory's RVA through the section table, the way it would for a file
 * on disk, finds nothing there. A real DLL keeps its exports in .rdata, so
 * this does too, on the page after the stubs and aligned like everything else.
 */
#define K32_STUB_RVA   0x1000u
#define K32_EXPORT_RVA 0x2000u
/*
 * SIXTEEN PAGES AND NOT THE TWO THIS FILLS. A loader that has the base reads
 * around it - section headers, a directory it does not find, a checksum over a
 * range the header declares - and every one of those reads is against an image
 * it believes is megabytes long. Measured: one sample faulted reading
 * base+0xdc97, which is past two pages and inside nothing. The extra fourteen
 * are zeroes, which is what a read of an unwritten part of a real image would
 * find often enough; the point is that it is a read and not a fault.
 */
#define K32_PAGES      16u

int kgenome_emu_unp_build_module_pe(struct kgenome_emu *e, unsigned bits, unsigned mi)
{
	uint8_t img[K32_PAGES * KGENOME_EMU_PAGE];
	uint64_t base = kgenome_emu_win_mod_base(mi, bits);
	unsigned all = kgenome_emu_win_api_count();
	unsigned mine[KGENOME_EMU_UNP_K32_MAX_EXPORTS], n = 0;
	unsigned ord[KGENOME_EMU_UNP_K32_MAX_EXPORTS];
	uint32_t name_rva[KGENOME_EMU_UNP_K32_MAX_EXPORTS];
	uint8_t *ex, *fns, *nms, *ords, *strs, *stub;
	uint32_t str_rva;
	unsigned i, j, opt, pe;

	if (!base)
		return 0;
	/* The functions this module owns, in the order the table lists them -
	 * which is the order kgenome_emu_win_api_slot counts in, so the n-th here
	 * is the n-th stub there. */
	{
		/*
		 * KERNELBASE EXPORTS WHAT KERNEL32 DOES, which is the truth
		 * about it: a modern kernel32 is mostly forwarders into
		 * kernelbase, so a resolver that goes looking there for a
		 * kernel32 name is right to. It has its own image - see
		 * KGENOME_EMU_WIN_MOD_KBASE - so a guest that patches one does not
		 * touch the other; only the LIST is shared.
		 */
		unsigned src = mi == KGENOME_EMU_WIN_MOD_KBASE
			     ? KGENOME_EMU_WIN_MOD_K32 : mi;

		for (i = 0; i < all && n < KGENOME_EMU_UNP_K32_MAX_EXPORTS; i++)
			if (kgenome_emu_win_api_mod(i) == src)
				mine[n++] = i;
	}
	/*
	 * A CAP THAT BITES IS A MISSING EXPORT, and a missing export is
	 * invisible from the outside: kgenome_emu_win_addr_of searches the whole
	 * table, so GetProcAddress still answers for a name past the cap and
	 * only a guest WALKING the directory ever notices. Measured, that is
	 * what an MPRESS stub does, and with the cap at 64 against 81 kernel32
	 * entries its search ran off the end of the list and resolved to zero.
	 */
	if (n == KGENOME_EMU_UNP_K32_MAX_EXPORTS)
		KOF_TRACE("[mod] %s: export list capped at %u\n",
			kgenome_emu_win_mod_name(mi), n);
	memset(img, 0, sizeof img);

	/* ---- the export arrays, and the strings they point at ---- */
	ex   = img + K32_EXPORT_RVA;
	fns  = ex + 40u;                       /* AddressOfFunctions */
	nms  = fns + 4u * n;                   /* AddressOfNames */
	ords = nms + 4u * n;                   /* AddressOfNameOrdinals */
	strs = ords + 2u * n;
	str_rva = (uint32_t)(strs - img);

	/* The module's own name first, because the directory points at it. */
	{
		const char *mn = kgenome_emu_win_mod_name(mi);
		unsigned len = (unsigned)strlen(mn) + 1u;

		memcpy(strs, mn, len);
		kof_st_le32(ex + 12u, str_rva);
		strs += len;
		str_rva += len;
	}

	for (i = 0; i < n; i++) {
		const char *nm = kgenome_emu_win_api_name(mine[i]);
		unsigned len = (unsigned)strlen(nm) + 1u;

		memcpy(strs, nm, len);
		name_rva[i] = str_rva;
		strs += len;
		str_rva += len;
		kof_st_le32(fns + 4u * i,
		      (uint32_t)(K32_STUB_RVA + i * KGENOME_EMU_WIN_STUB));
		ord[i] = i;
	}

	/* Sort the NAME array - the function array stays in ordinal order and
	 * the ordinal array is what ties the two together. */
	for (i = 1; i < n; i++) {
		unsigned k = ord[i];

		for (j = i; j > 0 &&
		     strcmp(kgenome_emu_win_api_name(mine[ord[j - 1]]),
			    kgenome_emu_win_api_name(mine[k])) > 0; j--)
			ord[j] = ord[j - 1];
		ord[j] = k;
	}
	for (i = 0; i < n; i++) {
		kof_st_le32(nms + 4u * i, name_rva[ord[i]]);
		kof_st_le16(ords + 2u * i, (uint16_t)ord[i]);
	}

	kof_st_le32(ex + 16u, 1u);                    /* Base: ordinals start at 1 */
	kof_st_le32(ex + 20u, n);                     /* NumberOfFunctions */
	kof_st_le32(ex + 24u, n);                     /* NumberOfNames */
	kof_st_le32(ex + 28u, (uint32_t)(fns - img));
	kof_st_le32(ex + 32u, (uint32_t)(nms - img));
	kof_st_le32(ex + 36u, (uint32_t)(ords - img));

	/* ---- the stubs ---- */
	stub = img + K32_STUB_RVA;
	for (i = 0; i < n; i++) {
		uint8_t *p = stub + i * KGENOME_EMU_WIN_STUB;
		unsigned argc = kgenome_emu_win_api_argc(mine[i]);

		p[0] = 0xb8;                            /* mov eax, imm32 */
		kof_st_le32(p + 1, kgenome_emu_win_api_trap(mine[i]));
		if (bits == 32u) {
			p[5] = 0xcd; p[6] = 0x80;       /* int 0x80 */
			if (argc) {
				p[7] = 0xc2;            /* ret argc*4 */
				kof_st_le16(p + 8, (uint16_t)(argc * 4u));
			} else {
				p[7] = 0xc3;            /* ret */
			}
		} else {
			p[5] = 0x0f; p[6] = 0x05;       /* syscall */
			p[7] = 0xc3;                    /* ret */
		}
	}

	/* ---- a header just real enough to be walked ---- */
	img[0] = 'M'; img[1] = 'Z';
	pe = 0x80u;
	kof_st_le32(img + 0x3cu, pe);
	img[pe] = 'P'; img[pe + 1] = 'E';
	kof_st_le16(img + pe + 4u, bits == 32u ? 0x014cu : 0x8664u);
	kof_st_le16(img + pe + 6u, 1u);                       /* one section */
	opt = bits == 32u ? 224u : 240u;
	kof_st_le16(img + pe + 20u, (uint16_t)opt);
	kof_st_le16(img + pe + 22u, 0x2102u);                 /* DLL | EXECUTABLE */

	{
		uint8_t *o = img + pe + 24u;
		unsigned dd;

		kof_st_le16(o, bits == 32u ? 0x010bu : 0x020bu);
		if (bits == 32u) {
			kof_st_le32(o + 28u, (uint32_t)base);         /* ImageBase */
			dd = 96u;
			kof_st_le32(o + 92u, 16u);                    /* NumberOfRvaAndSizes */
		} else {
			kof_st_le32(o + 24u, (uint32_t)base);
			kof_st_le32(o + 28u, (uint32_t)(base >> 32));
			dd = 112u;
			kof_st_le32(o + 108u, 16u);
		}
		kof_st_le32(o + 32u, KGENOME_EMU_PAGE);                   /* SectionAlignment */
		kof_st_le32(o + 36u, 0x200u);                         /* FileAlignment */
		kof_st_le32(o + 56u, KGENOME_EMU_UNP_K32_SPAN);                       /* SizeOfImage */
		kof_st_le32(o + 60u, KGENOME_EMU_PAGE);                   /* SizeOfHeaders */
		kof_st_le32(o + dd, K32_EXPORT_RVA);
		kof_st_le32(o + dd + 4u, (uint32_t)(str_rva - K32_EXPORT_RVA));

		{
			uint8_t *sec = o + opt;

			/* One section from the stubs to the end of the image,
			 * so both the code and the export directory are inside
			 * something the section table accounts for. */
			memcpy(sec, ".text", 6u);
			kof_st_le32(sec + 8u, KGENOME_EMU_UNP_K32_SPAN - K32_STUB_RVA);
			kof_st_le32(sec + 12u, K32_STUB_RVA);         /* VirtualAddress */
			kof_st_le32(sec + 16u, KGENOME_EMU_UNP_K32_SPAN - K32_STUB_RVA);
			kof_st_le32(sec + 20u, K32_STUB_RVA);         /* PointerToRawData */
			kof_st_le32(sec + 36u, 0x60000020u);          /* CODE|EXEC|READ */
		}
	}

	/*
	 * THE HEADER IS NOT EXECUTABLE, and mapping it as if it were costs a
	 * whole run.
	 *
	 * A guest that walks this export directory for a name kernel32 really
	 * exports but this table does not gets 0 back, adds it to the base and
	 * calls the module's own MZ header. Under one R|X mapping that is not
	 * an error: the zeroes decode as `add [rax],al` and the run marches
	 * forward two bytes at a time until something faults. Measured on an
	 * MPRESS sample, that was 310701 instructions ending in a fault at an
	 * address built out of header bytes, which says nothing about what went
	 * wrong.
	 *
	 * Windows maps a module's headers read-only, so doing the same turns it
	 * into an immediate fault AT THE BASE - which names the module and says
	 * the miss was an export lookup. The cost is one extra mapping and
	 * nothing per instruction.
	 */
	if (!kgenome_emu_map(e, base, img, K32_STUB_RVA, K32_STUB_RVA, KGENOME_EMU_R))
		return 0;
	if (!kgenome_emu_map(e, base + K32_STUB_RVA, img + K32_STUB_RVA,
			 sizeof img - K32_STUB_RVA, KGENOME_EMU_UNP_K32_SPAN - K32_STUB_RVA,
			 KGENOME_EMU_R | KGENOME_EMU_X))
		return 0;
	kgenome_emu_win_set_module(e, mi, base);
	return 1;
}

/*
 * ---- THE IMPORT TABLE THE LOADER WOULD HAVE FILLED ------------------------
 *
 * Every thunk whose name this environment has becomes the address of that
 * stub; every other thunk is left exactly as the file wrote it.
 *
 * LEFT, AND NOT ZEROED OR POINTED AT A STUB THAT RETURNS NOTHING. A call
 * through a thunk this cannot back is a call into a function that does not
 * exist, and the useful outcome is the fault - it names an address, the trace
 * prints it, and the next thing to implement is whatever was imported there.
 * A stub that shrugged and returned zero would turn that into a wrong answer
 * carried forward into memory the harvest then collects.
 */
/*
 * THE DIRECTORY IS NOT WALKED HERE AT ALL. It is walked once per object, into a
 * kgenome_pe_imptab, by whoever needs it first - the scanner keeps that table for
 * the object's life and the symbol block, the PE diagnose and this read the one
 * product - and this is only what the loader does with each import the table
 * holds: take the thunk's slot and, if this environment has the name, write the
 * stub's address there. A second walker lived here with its own section
 * arithmetic and its own limits (64 libraries, 8192 thunks in all, ordinals
 * skipped, no mapped-layout case); the parser's bounds - 256 libraries, 4096
 * thunks each - bound the INPUT, and an import the table holds is one this
 * fills, whichever library it is the 65th of.
 *
 * A caller with no scanner hands none and the run builds one with the same
 * builder (see kgenome_emu_unp_run_pe) - there is no second reader of the
 * directory for it to fall back on.
 */
unsigned kgenome_emu_unp_fill_iat_pe(struct kgenome_emu *e, const struct kgenome_pe_imptab *tab,
			    kof_buf f, const struct kgenome_pe_info *info,
			    uint64_t base, unsigned bits)
{
	unsigned width = bits == 32u ? 4u : 8u, filled = 0;
	uint32_t i;

	for (i = 0; i < tab->n; i++) {
		const struct kgenome_pe_imp *im = &tab->v[i];
		char nm[128];
		uint64_t addr;

		if (!im->nameoff)
			continue;       /* by ordinal: this has no names for those */
		/* The table keeps where the name is, not the name, and the stubs'
		 * names are matched on the whole of it. */
		if (!kgenome_pe_imp_name(f, im, nm, sizeof nm))
			continue;
		addr = kgenome_emu_win_addr_of(e, nm);
		if (!addr) {
			/* Which name the environment does not have is the only
			 * thing that says what to add to it: an unfilled thunk
			 * and a thunk nobody asked about are the same zero. */
			KOF_TRACE("[iat] miss %s\n", nm);
			continue;
		}
		/* The table reports the slot against the header's ImageBase; the
		 * image is mapped at `base`, which differs when the header says
		 * zero. */
		if (kgenome_emu_write(e, im->slot - info->image_base + base, &addr,
				  width))
			filled++;
	}
	if (tab->status != KGENOME_OK)
		KOF_TRACE("[iat] table is short for want of memory (%u)\n",
			  (unsigned)tab->n);
	return filled;
}

/*
 * THE STACK IS A STACK AND NOTHING ELSE.
 *
 * The ELF path builds argc, argv, envp and an auxv vector because an ELF entry
 * point is handed one and real stubs read it - UPX finds its own program
 * headers through AT_PHDR. A PE entry point is handed none of that: the loader
 * CALLS it, so the only thing on the stack a stub can legitimately read is a
 * return address.
 *
 * Writing an auxv here would crash nothing, because a PE stub never looks.
 * It would put a page of invented Linux process structure into the memory
 * image - and the written-memory harvest reads that image back. Bytes this
 * file made up are exactly the kind of thing that comes back later looking
 * like something the sample built.
 */
int kgenome_emu_unp_build_stack_pe(struct kgenome_emu *e, unsigned bits)
{
	uint64_t top = bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP;
	uint64_t len = (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE;
	uint64_t lo  = top - len;
	uint64_t ret = KGENOME_EMU_UNP_PE_RET_MAGIC;
	uint64_t sp;

	if (!kgenome_emu_map(e, lo, NULL, 0, len, KGENOME_EMU_R | KGENOME_EMU_W))
		return 0;

	/*
	 * HALFWAY DOWN, not at the top. A stub that pushes needs room below
	 * the pointer; a stub that indexes UPWARD off rsp - several decoders
	 * do, reading what the caller is expected to have left there - needs
	 * room above it. Starting at the very top makes the second kind fault
	 * immediately, on memory that was never the problem.
	 */
	sp = ((lo + len / 2u) & ~15ull) - 8u;
	if (!kgenome_emu_map(e, sp, (const uint8_t *)&ret,
			 bits == 32 ? 4u : 8u, 16u, KGENOME_EMU_R | KGENOME_EMU_W))
		return 0;

	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, sp);
	kgenome_emu_set_reg(e, KGENOME_EMU_RBP, sp);
	return 1;
}

unsigned kgenome_emu_unp_perm_of_pe(uint32_t p)
{
	unsigned r = 0;

	if (p & KGENOME_PE_PERM_R) r |= KGENOME_EMU_R;
	if (p & KGENOME_PE_PERM_W) r |= KGENOME_EMU_W;
	if (p & KGENOME_PE_PERM_X) r |= KGENOME_EMU_X;
	/*
	 * A section declaring no permission at all is still mapped readable.
	 * The characteristics field is something the FILE states and a packer
	 * is free to state nothing; the loader maps the section regardless,
	 * and a stub reading its own data out of a section it declared
	 * unreadable is a thing that works on Windows.
	 */
	return r ? r : KGENOME_EMU_R;
}

/*
 * WHY THERE IS NO WHY_LOADER HERE, AND THE MEASUREMENT THAT SETTLED IT.
 *
 * The ELF gate's third reason is a conjunction: a high-entropy blob in a
 * non-executable segment AND the file imports something that can turn memory
 * into code. It fires on none of 846 clean ELF binaries, and the half doing
 * that work is the IMPORT one - mprotect and memfd_create are rare in ordinary
 * Linux programs, so requiring one is a real filter.
 *
 * Transplanted to PE it collapses, because the Windows equivalent is not rare.
 * Measured over 2678 clean x86/x64 PEs from System32 and SysWOW64:
 *
 *   contains VirtualAlloc / VirtualProtect / the Nt forms   445   (16.6%)
 *   high-entropy blob >= 16KB in a non-exec section         100
 *   BOTH - what the ELF rule would call a loader             22
 *
 * Twenty-two false positives, and they are not obscure: setupapi.dll,
 * urlmon.dll, msi.dll, mmc.exe, the MFC runtimes. Raising the blob threshold
 * does not rescue it either - 64KB still leaves 7 and 256KB still leaves 2,
 * and by then the rule has stopped reaching the staged payloads it exists for.
 *
 * So the reason is absent rather than present-and-loose. What would replace it
 * is a discriminator that is actually Windows-shaped - a blob beside a TINY
 * import table, since a packer imports two or three functions where a real
 * program imports hundreds, and pe_sym.c already parses the table to count -
 * and that is a calibration job with its own corpus, not a constant to guess
 * at here.
 */
