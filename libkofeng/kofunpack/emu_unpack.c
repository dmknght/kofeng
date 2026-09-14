/*
 * emu_unpack.c - see emu_unpack.h.
 */

#include <stdlib.h>
#include <string.h>

#include "emu_unpack.h"
#include "../kofeng.h"

/* Where an ET_DYN object is placed, matching what a loader with ASLR off does.
 * The value matters only in that a stub reading its own addresses must find
 * them consistent; any base a real loader could have chosen will do. */
/*
 * p_type for PT_LOAD. The public view keeps the raw value, and this is the only
 * one it takes to answer "is this mapped"; the collector's own copy is not
 * exported and duplicating its whole table for one constant would be worse
 * than naming the one constant.
 */
#define PT_LOAD_TYPE  1u

#define DYN_BIAS      0x555555554000ull

/* Where a file with no usable PT_LOAD gets mapped instead. */
#define FLAT_BASE     0x0000000000400000ull

#define STACK_TOP     0x00007ffffffff000ull
/*
 * The 32-bit stack, and it has to be its own number rather than the one above
 * masked down.
 *
 * A 32-bit guest computes stack addresses in 32 bits, so an esp of
 * 0x7ffffffff000 truncates to 0xfffff000 the moment the code touches it - and
 * then writes there, to a page nothing mapped. Measured: bloxor faulted on its
 * second instruction, writing to 0xffffef34. This is where Linux actually puts
 * a 32-bit stack, so the guest's own arithmetic lands inside what is mapped.
 */
#define STACK_TOP_32  0xfffff000ull
#define STACK_PAGES   64u

/*
 * The threshold, in eighths of a bit, over PT_LOAD|PF_X.
 *
 * Eighths rather than a float: this runs inside the engine, and an integer
 * comparison cannot round differently on a different build.
 */
#define DENSE_EIGHTHS  60u             /* 7.5 bits per byte */
#define DENSE_MIN      512u            /* below this the estimate is noise */

/*
 * The loader test: a ciphertext block in a non-code segment, and an import
 * that can make memory executable. See KOF_EMU_UNP_WHY_LOADER.
 *
 * The window is 512 bytes because entropy measured over fewer is not stable:
 * 256 uniformly random bytes score only ~7.1 bits, below the threshold, purely
 * from the finite sample. At 512 the estimate settles - random and ciphertext
 * read ~7.5, ordinary code reads ~4.9 - so the two separate cleanly. The size
 * threshold is what earns the near-zero false positives: measured over 846
 * clean binaries, 16 KB of contiguous high-entropy in a non-code segment beside
 * the import fires on one - git-lfs, whose embedded assets are genuinely that
 * big - where 8 KB fires on three. The cost of the threshold is reach: an
 * encrypted payload smaller than 16 KB, a short stager most of all, slips under
 * it. That is the deliberate trade - a block this size is what a stray
 * high-entropy field cannot reach and a real staged payload clears easily - and
 * it means the signal is for the LARGE encrypted payload, not the small stager.
 */
#define LOADER_EIGHTHS 57u             /* 7.125 bits per byte, over a window */
#define LOADER_WINDOW  512u            /* the entropy is measured this wide */
#define LOADER_BLOB    16384u          /* and this many high bytes in a row */

/* ---- the gate ------------------------------------------------------------ */

/*
 * Shannon entropy of a byte histogram, in eighths of a bit, without floating
 * point: for each populated bucket, log2(n/total) is accumulated from an
 * integer log2 plus a linear correction. The result is only ever compared
 * against a threshold, so the correction only has to keep the ORDER right, and
 * it is checked against the float version in tests/unit/emu_gate.c.
 */
static unsigned entropy_eighths(const uint32_t *hist, uint64_t total)
{
	/* One implementation, in kofeng.c, because the tools show this number
	 * beside a region and were about to grow a second copy of it. */
	return (unsigned)kof_entropy_hist(hist, total);
}

/*
 * The longest run of high-entropy windows anywhere in a non-executable
 * PT_LOAD, in bytes. Windows are stepped by their own width, so the answer is
 * a multiple of LOADER_WINDOW; that is deliberate, because a payload straddling
 * a window boundary still fills whole windows on either side of it.
 */
static uint64_t loader_blob(const struct kof_elf_info *info,
			    const uint8_t *file, uint64_t n)
{
	uint64_t best = 0, i;

	for (i = 0; i < info->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *s = &info->seg[i];
		uint64_t off = s->file_off, len = s->file_size, at, run = 0;

		if (s->type != PT_LOAD_TYPE || (s->perm & KOF_PERM_X) || !len)
			continue;
		if (off >= n)
			continue;
		if (len > n - off)
			len = n - off;
		for (at = 0; at + LOADER_WINDOW <= len; at += LOADER_WINDOW) {
			uint32_t hist[256];
			uint64_t k;

			memset(hist, 0, sizeof hist);
			for (k = 0; k < LOADER_WINDOW; k++)
				hist[file[off + at + k]]++;
			if (entropy_eighths(hist, LOADER_WINDOW) >= LOADER_EIGHTHS) {
				run += LOADER_WINDOW;
				if (run > best)
					best = run;
			} else {
				run = 0;
			}
		}
	}
	return best;
}

/*
 * Does the file import a way to make memory executable? The name lives in the
 * dynamic string table, which is loaded and so is somewhere in the file's
 * bytes; a substring search finds it without a second parse and without
 * depending on section headers a hostile object may have stripped. A benign
 * mention in .rodata would match too, but only in concert with an 8 KB
 * ciphertext block, and that pair is what the measurement cleared.
 */
static int loader_imports_exec(const uint8_t *file, uint64_t n)
{
	static const char *const want[] = { "mprotect", "memfd_create" };
	unsigned w;

	for (w = 0; w < sizeof want / sizeof want[0]; w++) {
		uint64_t m = strlen(want[w]) + 1;   /* include the NUL: a symbol
						     * name, not a random hit */
		uint64_t i;

		if (m > n)
			continue;
		for (i = 0; i + m <= n; i++)
			if (!memcmp(file + i, want[w], m))
				return 1;
	}
	return 0;
}

enum kof_emu_unp_why kof_emu_unp_gate(const struct kof_obj_ctx *ctx,
				      const struct kof_elf_info *info,
				      const uint8_t *file, uint64_t n)
{
	static const uint64_t unloadable =
		KOF_ELF_ANOM_NO_LOAD_SEGMENT | KOF_ELF_ANOM_PHOFF_PAST_EOF |
		KOF_ELF_ANOM_PHENTSIZE_ODD   | KOF_ELF_ANOM_TRUNCATED_HEADER |
		KOF_ELF_ANOM_ENTRY_UNMAPPED  | KOF_ELF_ANOM_ENTRY_ZEROFILL |
		KOF_ELF_ANOM_ENTRY_NOT_EXEC;
	uint32_t hist[256];
	uint64_t total = 0;
	uint32_t i;

	if (!ctx || !info || !info->valid || !file)
		return KOF_EMU_UNP_NO;
	/*
	 * x86 AND x86-64, since the emulator learned a 32-bit mode - see
	 * kof_emu_cfg.bits. It was amd64 only because the interpreter was, and
	 * the note that used to stand here said the measurement supported that:
	 * every one of the 294 dense objects in the clean-corpus run was amd64.
	 * That is still true of the DENSE gate and says nothing about the
	 * others - the shape rule in bases/heur/shellcode_00.c fires on 32-bit
	 * payloads and asks for the emulator on them, and until now the ask
	 * arrived here and was refused.
	 *
	 * Everything else is still refused: bddisasm decodes these two and an
	 * ARM object would be started and stopped on its first instruction,
	 * which costs a page table and teaches nothing.
	 */
	if (ctx->arch != KOF_ARCH_X86_64 && ctx->arch != KOF_ARCH_X86)
		return KOF_EMU_UNP_NO;

	/*
	 * Broken first, because it is the stronger statement. A file whose
	 * header cannot be loaded has already defeated every module that needs
	 * structure, and the density test would not even find its code.
	 */
	if (info->anomalies & unloadable)
		return KOF_EMU_UNP_WHY_BROKEN;

	memset(hist, 0, sizeof hist);
	for (i = 0; i < info->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *s = &info->seg[i];
		uint64_t off = s->file_off, len = s->file_size, k;

		if (s->type != PT_LOAD_TYPE || !(s->perm & KOF_PERM_X) || !len)
			continue;
		if (off >= n)
			continue;
		if (len > n - off)
			len = n - off;
		for (k = 0; k < len; k++)
			hist[file[off + k]]++;
		total += len;
	}
	if (total >= DENSE_MIN &&
	    entropy_eighths(hist, total) >= DENSE_EIGHTHS)
		return KOF_EMU_UNP_WHY_DENSE;

	/*
	 * The code is ordinary, so nothing above fired - but a ciphertext block
	 * in a non-code segment beside an import that can execute memory is the
	 * C-loader carrying an encrypted payload. Last because it is the
	 * narrowest statement and the most work: two passes over the file that
	 * the two cheaper tests above did not need.
	 */
	if (loader_blob(info, file, n) >= LOADER_BLOB &&
	    loader_imports_exec(file, n))
		return KOF_EMU_UNP_WHY_LOADER;

	return KOF_EMU_UNP_NO;
}

/* ---- building a process image -------------------------------------------- */

/*
 * The stack, laid out the way Linux lays it out and not merely somewhere the
 * registers point at.
 *
 * High to low: a terminating NULL, the argument strings, then auxv, envp, argv
 * and argc, with argc at the lowest address and rsp on it. Putting the block
 * lower and the strings just above it looks equivalent and is not: UPX walks to
 * the END of the block to find the stack top and then relocates the whole thing
 * relative to that. Measured - with the block placed low, it read its
 * relocation source from a megabyte above anything that had been written, and
 * copied zeroes over the trampoline it was about to jump through.
 */
static int build_stack(struct kof_emu *e, uint64_t entry, uint64_t phdr_va,
		       uint64_t phent, uint64_t phnum, uint64_t base,
		       unsigned bits)
{
	static const char nm[] = "/tmp/a";
	uint8_t zero[16] = { 0 };
	uint64_t v[32], sp, strv;
	uint64_t top = bits == 32 ? STACK_TOP_32 : STACK_TOP;
	int k = 0;

	if (!kof_emu_map(e, top - (uint64_t)STACK_PAGES * KOF_EMU_PAGE,
			 NULL, 0, (uint64_t)STACK_PAGES * KOF_EMU_PAGE,
			 KOF_EMU_R | KOF_EMU_W))
		return 0;

	strv = (top - 16u - sizeof nm) & ~15ull;
	kof_emu_map(e, strv, (const uint8_t *)nm, sizeof nm, sizeof nm,
		    KOF_EMU_R | KOF_EMU_W);
	kof_emu_map(e, top - 16u, zero, 8, 16, KOF_EMU_R | KOF_EMU_W);

	v[k++] = 1;                  /* argc      */
	v[k++] = strv;               /* argv[0]   */
	v[k++] = 0;                  /* argv NULL */
	v[k++] = 0;                  /* envp NULL */
	v[k++] = 3;  v[k++] = phdr_va;     /* AT_PHDR   - an ADDRESS, see below */
	v[k++] = 4;  v[k++] = phent;       /* AT_PHENT  */
	v[k++] = 5;  v[k++] = phnum;       /* AT_PHNUM  */
	v[k++] = 6;  v[k++] = KOF_EMU_PAGE;/* AT_PAGESZ */
	v[k++] = 9;  v[k++] = entry;       /* AT_ENTRY  */
	v[k++] = 7;  v[k++] = base;        /* AT_BASE   */
	v[k++] = 11; v[k++] = 0;           /* AT_UID    */
	v[k++] = 0;  v[k++] = 0;           /* AT_NULL   */

	sp = (strv - (uint64_t)k * 8u) & ~15ull;
	if (!kof_emu_map(e, sp, (const uint8_t *)v, (uint64_t)k * 8u,
			 (uint64_t)k * 8u, KOF_EMU_R | KOF_EMU_W))
		return 0;
	kof_emu_set_reg(e, KOF_EMU_RSP, sp);
	return 1;
}

static unsigned perm_of(uint32_t p)
{
	unsigned r = 0;

	if (p & KOF_PERM_R) r |= KOF_EMU_R;
	if (p & KOF_PERM_W) r |= KOF_EMU_W;
	if (p & KOF_PERM_X) r |= KOF_EMU_X;
	return r ? r : KOF_EMU_R;
}

struct kof_emu *kof_emu_unp_run(const uint8_t *file, uint64_t n,
				const struct kof_elf_info *info,
				uint64_t max_insn, uint64_t max_pages,
				struct kof_emu_unp_report *rep)
{
	struct kof_emu_cfg cfg;
	struct kof_emu *e;
	uint64_t bias, entry = 0, phdr_va = 0, lowest_x = 0, base_lo = ~0ull;
	uint32_t i, mapped = 0;
	int improvised = 0;
	/*
	 * Ranges holding REAL FILE BYTES, which is not the same as ranges that
	 * are mapped: p_memsz outlives p_filesz, so a segment contributes
	 * zero-filled pages past the content it actually carries, and a
	 * truncated file contributes a great many of them.
	 */
	uint64_t back_lo[KOF_ELF_MAX_SEGMENTS], back_hi[KOF_ELF_MAX_SEGMENTS];
	uint32_t n_back = 0;

	if (rep)
		memset(rep, 0, sizeof *rep);
	if (!file || !n || !info || !info->valid)
		return NULL;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = max_insn;
	cfg.max_pages = max_pages;
	/*
	 * The width comes from the FILE, not from a caller's opinion: an ELF32
	 * holds i386 code and an ELF64 holds amd64, and the parser has already
	 * normalised which one this is. Reading it here is what keeps the two
	 * from ever disagreeing.
	 */
	cfg.bits = info->elf_class == KOF_ELFCLASS_32 ? 32u : 64u;
	e = kof_emu_new(&cfg);
	if (!e)
		return NULL;

	/* ET_DYN is linked at zero and a loader picks the base; ET_EXEC carries
	 * its own addresses and must be left where it says it is. */
	bias = (info->e_type == KOF_ELF_DYN && info->min_vaddr == 0) ? DYN_BIAS : 0;

	for (i = 0; i < info->seg_count && i < KOF_ELF_MAX_SEGMENTS; i++) {
		const struct kof_elf_seg *s = &info->seg[i];
		uint64_t off = s->file_off, fsz = s->file_size, va;

		if (s->type != PT_LOAD_TYPE)
			continue;
		if (off >= n)
			continue;              /* declared past the file's end */
		if (fsz > n - off)
			fsz = n - off;         /* truncated: map what exists */
		va = s->mem_addr + bias;
		if (!kof_emu_map(e, va, file + off, fsz,
				 s->mem_size > fsz ? s->mem_size : fsz,
				 perm_of(s->perm)))
			continue;
		mapped++;
		if (fsz && n_back < KOF_ELF_MAX_SEGMENTS) {
			back_lo[n_back] = va;
			back_hi[n_back] = va + fsz;
			n_back++;
		}
		if (va < base_lo)
			base_lo = va;
		/*
		 * AT_PHDR is an ADDRESS and a stub reads its own program
		 * headers through it - UPX finds its packed data that way.
		 * Passing the file offset pointed it at an unmapped address
		 * near zero, where it read an all-zero header and unpacked
		 * nothing.
		 */
		if (info->phoff >= off && info->phoff < off + fsz)
			phdr_va = va + (info->phoff - off);
		if ((s->perm & KOF_PERM_X) && (!lowest_x || va < lowest_x)) {
			/*
			 * Where code could start in this segment, which is not
			 * where the segment starts. The first PT_LOAD of an
			 * ordinary binary begins at file offset 0, so its first
			 * bytes are the ELF header and the program header
			 * table - guessing an entry there means decoding
			 * "\x7fELF" as instructions, which is knowably wrong
			 * before it is tried.
			 */
			lowest_x = va;
			if (!off && info->hdr_claim_len)
				lowest_x += (info->hdr_claim_len + 15u) & ~15ull;
		}
	}

	/*
	 * THE FAIL-SAFE: nothing could be mapped from the header.
	 *
	 * The object still has bytes and they still mean something - a packer
	 * that overwrote its own program header table did not overwrite its
	 * stub. Mapping the file flat at a plausible base is what is left, and
	 * it is right often enough to be worth doing: the addresses inside a
	 * self-contained stub are relative to where it finds itself, which is
	 * exactly what a flat map preserves.
	 */
	if (!mapped) {
		uint64_t at = (info->min_vaddr != KOF_NA && info->min_vaddr)
			      ? (info->min_vaddr & ~(uint64_t)(KOF_EMU_PAGE - 1u))
			      : FLAT_BASE;

		if (!kof_emu_map(e, at, file, n, n,
				 KOF_EMU_R | KOF_EMU_W | KOF_EMU_X)) {
			kof_emu_free(e);
			return NULL;
		}
		bias = at;
		base_lo = at;
		lowest_x = at;
		improvised = 1;
		if (info->phoff && info->phoff < n)
			phdr_va = at + info->phoff;
	}

	/*
	 * Where to start, in order of how much the file is trusted for it.
	 *
	 * The declared entry is used whenever it lands on something mapped -
	 * including when the collector called it unmapped, because "unmapped"
	 * was decided against the header's own segment table and the flat
	 * fallback above has since mapped everything. Only when there is
	 * nothing at that address does this fall back to the first executable
	 * mapping, and that is a guess and is reported as one.
	 */
	entry = info->entry_addr ? info->entry_addr + (mapped ? bias : 0) : 0;
	if (!mapped && info->entry_addr && info->entry_addr < n)
		entry = bias + info->entry_addr;   /* flat: treat it as an offset */

	/*
	 * THE ENTRY HAS TO BE IN THE FILE, and being mapped is not that.
	 *
	 * A truncated object still has every address its header declares -
	 * p_memsz covers them - so the declared entry reads back as sixteen
	 * zero bytes and decodes as "add [rax], al". That is what a truncated
	 * UPX sample looks like from here, and it is the common case rather
	 * than a corner: the UPX stub sits PAST the compressed data, so a file
	 * cut short is a file whose entry point is exactly the part that is
	 * missing. Measured on one - a 240 KB object whose first PT_LOAD claims
	 * 2.3 MB and whose entry is at offset 2 373 576.
	 *
	 * Improvising an entry there produced a run that faulted on its second
	 * instruction and told the reader nothing. Refusing says the true
	 * thing, and it is a fact about the FILE: the code that would have
	 * unpacked it is not present. The static unpacker still recovers what
	 * the file does hold, which is why it succeeds where this cannot.
	 */
	if (entry) {
		int backed = !mapped;   /* a flat map is file bytes throughout */

		for (i = 0; !backed && i < n_back; i++)
			if (entry >= back_lo[i] && entry < back_hi[i])
				backed = 1;
		if (!backed) {
			if (rep)
				rep->refused = "the entry point is past the "
					       "bytes the file actually holds";
			kof_emu_free(e);
			return NULL;
		}
	}

	/*
	 * Only now, and only for a header that could not be read at all. When
	 * the header IS readable its entry is the best fact available, and
	 * guessing past it would be substituting a worse one.
	 */
	if (!entry) {
		if (!improvised && mapped) {
			if (rep)
				rep->refused = "the object declares no entry "
					       "point";
			kof_emu_free(e);
			return NULL;
		}
		entry = lowest_x ? lowest_x : base_lo;
		improvised = 1;
	}
	if (!entry) {
		kof_emu_free(e);
		return NULL;
	}

	if (rep) {
		uint64_t top = cfg.bits == 32 ? STACK_TOP_32 : STACK_TOP;

		rep->stack_hi = top;
		rep->stack_lo = top - (uint64_t)STACK_PAGES * KOF_EMU_PAGE;
	}
	if (!build_stack(e, entry, phdr_va ? phdr_va : base_lo,
			 info->phentsize, info->phnum, base_lo, cfg.bits)) {
		kof_emu_free(e);
		return NULL;
	}
	kof_emu_set_self(e, file, n);
	kof_emu_set_rip(e, entry);

	/*
	 * THE GENERAL REGISTERS POINT AT THE ENTRY, not at zero.
	 *
	 * A whole family of encoders needs this. The Alpha2 unicode decoders
	 * take a BUFFER REGISTER - the caller is expected to leave a register
	 * pointing at the shellcode, because an exploit that lands one there is
	 * how they are used - and then index from it. Started with zeros,
	 * x86_unicode_upper read address 0x46 on its twenty-first instruction
	 * and faulted; every alphanumeric decoder of that family did the same.
	 *
	 * Zero was never right anyway. The ABI leaves these UNDEFINED at entry,
	 * so a real process finds whatever the loader left - never a page of
	 * zeros - and nothing that runs correctly may depend on their value.
	 * Pointing them at the entry is both closer to what a real run looks
	 * like and the one value that makes this family work.
	 *
	 * RSP and RBP are left alone: the stack is real and was just built, and
	 * overwriting the pointer to it would break every stub that pushes.
	 */
	{
		static const unsigned seed[] = {
			KOF_EMU_RAX, KOF_EMU_RCX, KOF_EMU_RDX, KOF_EMU_RBX,
			KOF_EMU_RSI, KOF_EMU_RDI
		};
		unsigned k;

		for (k = 0; k < sizeof seed / sizeof seed[0]; k++)
			kof_emu_set_reg(e, seed[k], entry);
	}

	{
		enum kof_emu_stop st = kof_emu_run(e);
		uint32_t it = 0, k = 0;
		uint64_t va, len;
		const uint8_t *bytes;

		if (rep) {
			rep->stop = st;
			rep->insn = kof_emu_insn_count(e);
			rep->entry = entry;
			rep->improvised = improvised;
			rep->detail = kof_emu_stop_detail(e);
			for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes,
							   &len); )
				k++;
			rep->images = k;
			for (it = 0, k = 0;
			     kof_emu_next_written(e, &it, &va, &bytes, &len); )
				k++;
			rep->written = k;
		}
	}
	return e;
}

/* ---- the same two jobs, for a PE ------------------------------------------
 *
 * See emu_unpack.h for why a PE is worth running with no API layer behind it.
 * Everything below is the PE restatement of the ELF half above; where a
 * threshold or a rule is the same it IS the same constant, not a second copy
 * of the number that can drift from it.
 */

/*
 * WHERE A PE GOES WHEN IT DECLARES NOWHERE.
 *
 * ImageBase 0 is legal and a loader is then free to place the image. This has
 * no relocation machinery and a stub's absolute addresses are written against
 * the base the linker chose, so the useful default is the one the toolchains
 * use: 0x400000 for a 32-bit image and 0x140000000 for 64-bit. Both are where
 * an unrelocated image expects to find itself.
 */
#define PE_BASE_32    0x0000000000400000ull
#define PE_BASE_64    0x0000000140000000ull

/*
 * THE RETURN ADDRESS A PE ENTRY POINT IS CALLED WITH, and it deliberately
 * points at nothing mapped. A stub that RETURNS rather than jumping to its
 * payload then stops with a fault at an address that is recognisably this
 * value, instead of running on through whatever bytes happened to follow.
 */
#define PE_RET_MAGIC  0x00000000deadf00dull

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
static int build_stack_pe(struct kof_emu *e, unsigned bits)
{
	uint64_t top = bits == 32 ? STACK_TOP_32 : STACK_TOP;
	uint64_t len = (uint64_t)STACK_PAGES * KOF_EMU_PAGE;
	uint64_t lo  = top - len;
	uint64_t ret = PE_RET_MAGIC;
	uint64_t sp;

	if (!kof_emu_map(e, lo, NULL, 0, len, KOF_EMU_R | KOF_EMU_W))
		return 0;

	/*
	 * HALFWAY DOWN, not at the top. A stub that pushes needs room below
	 * the pointer; a stub that indexes UPWARD off rsp - several decoders
	 * do, reading what the caller is expected to have left there - needs
	 * room above it. Starting at the very top makes the second kind fault
	 * immediately, on memory that was never the problem.
	 */
	sp = ((lo + len / 2u) & ~15ull) - 8u;
	if (!kof_emu_map(e, sp, (const uint8_t *)&ret,
			 bits == 32 ? 4u : 8u, 16u, KOF_EMU_R | KOF_EMU_W))
		return 0;

	kof_emu_set_reg(e, KOF_EMU_RSP, sp);
	kof_emu_set_reg(e, KOF_EMU_RBP, sp);
	return 1;
}

static unsigned perm_of_pe(uint32_t p)
{
	unsigned r = 0;

	if (p & KOF_PE_PERM_R) r |= KOF_EMU_R;
	if (p & KOF_PE_PERM_W) r |= KOF_EMU_W;
	if (p & KOF_PE_PERM_X) r |= KOF_EMU_X;
	/*
	 * A section declaring no permission at all is still mapped readable.
	 * The characteristics field is something the FILE states and a packer
	 * is free to state nothing; the loader maps the section regardless,
	 * and a stub reading its own data out of a section it declared
	 * unreadable is a thing that works on Windows.
	 */
	return r ? r : KOF_EMU_R;
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

/*
 * The longest run of high-entropy windows ANYWHERE in the file - not per
 * section, which is the point of it.
 *
 * loader_blob asks the same question of one segment at a time because on ELF
 * the interesting statement is WHICH segment holds the ciphertext. Here the
 * statement has already been made by the entry point sitting in an appended
 * section, and where the packer then parked its compressed original - a
 * section, the overlay, past the last section header - is its own business.
 * Asking per section would have missed exactly the case this exists for.
 */
static uint64_t blob_anywhere(const uint8_t *file, uint64_t n)
{
	uint64_t best = 0, run = 0, at;

	for (at = 0; at + LOADER_WINDOW <= n; at += LOADER_WINDOW) {
		uint32_t hist[256];
		uint64_t k;

		memset(hist, 0, sizeof hist);
		for (k = 0; k < LOADER_WINDOW; k++)
			hist[file[at + k]]++;
		if (entropy_eighths(hist, LOADER_WINDOW) >= LOADER_EIGHTHS) {
			run += LOADER_WINDOW;
			if (run > best)
				best = run;
		} else {
			run = 0;
		}
	}
	return best;
}

enum kof_emu_unp_why kof_emu_unp_gate_pe(const struct kof_obj_ctx *ctx,
					 const struct kof_pe_info *info,
					 const uint8_t *file, uint64_t n)
{
	/*
	 * THE ANOMALIES THAT MEAN "THIS CANNOT BE LOADED AS WRITTEN" - the PE
	 * half of `unloadable`, and deliberately not the whole anomaly list.
	 * Most of the twenty-seven are notes about a file that loads perfectly
	 * well. These are the ones where the header has stopped describing the
	 * image, which is when an interpreter - needing only somewhere to
	 * start - is the only reader left.
	 */
	static const uint64_t unloadable =
		KOF_PE_ANOM_SECTAB_PAST_EOF | KOF_PE_ANOM_SEC_PAST_EOF |
		KOF_PE_ANOM_ENTRY_UNMAPPED  | KOF_PE_ANOM_ENTRY_ZEROFILL |
		KOF_PE_ANOM_ENTRY_NOT_EXEC  | KOF_PE_ANOM_NSEC_ZERO;
	uint32_t hist[256];
	uint64_t total = 0;
	uint32_t i;

	if (!ctx || !info || !info->valid || !file)
		return KOF_EMU_UNP_NO;
	/*
	 * bddisasm decodes x86 and x86-64 and nothing else, so an ARM64 PE is
	 * refused HERE rather than started and left to fault on its first
	 * instruction - which would spend a budget to learn something the
	 * machine field said for free.
	 */
	if (ctx->arch != KOF_ARCH_X86_64 && ctx->arch != KOF_ARCH_X86)
		return KOF_EMU_UNP_NO;

	if (info->anomalies & unloadable)
		return KOF_EMU_UNP_WHY_BROKEN;

	memset(hist, 0, sizeof hist);
	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &info->sec[i];
		uint64_t off = s->file_off, len = s->file_size, k;

		if (!(s->perm & KOF_PE_PERM_X) || !len)
			continue;
		if (off >= n)
			continue;
		if (len > n - off)
			len = n - off;
		for (k = 0; k < len; k++)
			hist[file[off + k]]++;
		total += len;
	}
	/*
	 * THE SAME 7.5 BITS PER BYTE AS THE ELF SIDE, and measured to be in
	 * the same place. Over those 2678 clean PEs the executable sections
	 * fall almost entirely between 6.0 and 7.0 bits - 1669 of them - and
	 * only 4 files reach 7.0 at all. One clears 7.5. Compiled code simply
	 * is not this dense, and something that is has written its own code
	 * before running it.
	 */
	if (total >= DENSE_MIN &&
	    entropy_eighths(hist, total) >= DENSE_EIGHTHS)
		return KOF_EMU_UNP_WHY_DENSE;

	/*
	 * AND THE PACKER THAT LEFT ITS COMPRESSED DATA SOMEWHERE DENSE CANNOT
	 * LOOK - see KOF_EMU_UNP_WHY_APPENDED for the measurement.
	 *
	 * Two sections at least, so "the LAST section" is a statement about an
	 * arrangement rather than a tautology about a file that has only one.
	 */
	if (info->sec_count >= 2u &&
	    info->entry_rva &&
	    info->entry_sec == info->sec_count - 1u &&
	    blob_anywhere(file, n) >= LOADER_BLOB)
		return KOF_EMU_UNP_WHY_APPENDED;

	return KOF_EMU_UNP_NO;
}

struct kof_emu *kof_emu_unp_run_pe(const uint8_t *file, uint64_t n,
				   const struct kof_pe_info *info,
				   uint64_t max_insn, uint64_t max_pages,
				   struct kof_emu_unp_report *rep)
{
	struct kof_emu_cfg cfg;
	struct kof_emu *e;
	uint64_t base, entry = 0, lowest_x = 0, base_lo = ~0ull;
	uint64_t back_lo[KOF_PE_MAX_SECTIONS + 1];
	uint64_t back_hi[KOF_PE_MAX_SECTIONS + 1];
	uint32_t n_back = 0, i, mapped = 0;
	int improvised = 0;

	if (rep)
		memset(rep, 0, sizeof *rep);
	if (!file || !n || !info || !info->valid)
		return NULL;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = max_insn;
	cfg.max_pages = max_pages;
	/*
	 * The width comes from the FILE, exactly as on the ELF side: PE32
	 * holds i386 code and PE32+ holds amd64, and the parser has already
	 * decided which magic this carries.
	 */
	cfg.bits = info->pe32_plus ? 64u : 32u;
	e = kof_emu_new(&cfg);
	if (!e)
		return NULL;

	base = info->image_base ? info->image_base
			        : (cfg.bits == 64 ? PE_BASE_64 : PE_BASE_32);

	/*
	 * THE HEADERS ARE MAPPED, and that is not tidiness.
	 *
	 * A PE is mapped from its first byte: the MZ header, the NT headers
	 * and the section table are all readable at ImageBase in a real
	 * process, and stubs read them. The ones that matter here walk their
	 * own section table to find the compressed stream - the PE analogue of
	 * the AT_PHDR trick the ELF path had to be taught - and a stub that
	 * finds zeros where its section table should be unpacks nothing, with
	 * no fault and no message.
	 */
	if (info->size_of_headers && info->size_of_headers <= n) {
		uint64_t hl = info->size_of_headers;

		if (kof_emu_map(e, base, file, hl, hl, KOF_EMU_R)) {
			mapped++;
			back_lo[n_back] = base;
			back_hi[n_back] = base + hl;
			n_back++;
			base_lo = base;
		}
	}

	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &info->sec[i];
		uint64_t off = s->file_off, fsz = s->file_size, va, msz;

		if (!s->mem_rva && !s->file_size)
			continue;
		va = base + s->mem_rva;
		if (off >= n)
			fsz = 0;               /* declared past the file's end */
		else if (fsz > n - off)
			fsz = n - off;         /* truncated: map what exists */
		/*
		 * VirtualSize governs the MAPPING and SizeOfRawData the
		 * CONTENT, and a packer's output is where they differ most:
		 * the section its payload decompresses into has a large
		 * VirtualSize and no file bytes at all. Mapping only the raw
		 * size would leave the stub writing into nothing.
		 */
		msz = s->mem_size > fsz ? s->mem_size : fsz;
		if (!msz)
			continue;
		if (!kof_emu_map(e, va, fsz ? file + off : NULL, fsz, msz,
				 perm_of_pe(s->perm)))
			continue;
		mapped++;
		if (fsz && n_back < KOF_PE_MAX_SECTIONS + 1) {
			back_lo[n_back] = va;
			back_hi[n_back] = va + fsz;
			n_back++;
		}
		if (va < base_lo)
			base_lo = va;
		if ((s->perm & KOF_PE_PERM_X) && (!lowest_x || va < lowest_x))
			lowest_x = va;
	}

	/*
	 * THE FAIL-SAFE, and the reasoning is the ELF one unchanged: a packer
	 * that overwrote its own section table did not overwrite its stub, and
	 * the addresses inside a self-contained stub are relative to where it
	 * finds itself - which is exactly what a flat map preserves.
	 */
	if (!mapped) {
		if (!kof_emu_map(e, base, file, n, n,
				 KOF_EMU_R | KOF_EMU_W | KOF_EMU_X)) {
			kof_emu_free(e);
			return NULL;
		}
		base_lo    = base;
		lowest_x   = base;
		improvised = 1;
		back_lo[0] = base;
		back_hi[0] = base + n;
		n_back     = 1;
	}

	if (info->entry_rva)
		entry = base + info->entry_rva;

	/*
	 * THE ENTRY HAS TO BE ON BYTES THE FILE ACTUALLY HOLDS.
	 *
	 * Word for word the ELF rule, and on PE if anything more common: a
	 * section's VirtualSize covers addresses its SizeOfRawData does not,
	 * so the declared entry of a truncated file reads back as zeros and
	 * decodes as "add [rax], al". Refusing says the true thing - the code
	 * that would have unpacked this is not present - and leaves the static
	 * unpacker to recover what the file does hold.
	 */
	if (entry) {
		int backed = 0;

		for (i = 0; i < n_back; i++)
			if (entry >= back_lo[i] && entry < back_hi[i])
				backed = 1;
		if (!backed) {
			if (rep)
				rep->refused = "the entry point is past the "
					       "bytes the file actually holds";
			kof_emu_free(e);
			return NULL;
		}
	}

	if (!entry) {
		/*
		 * A readable header that declares no entry is a STATEMENT, not
		 * a gap, and guessing past it would substitute a worse fact.
		 * Only a header that could not be read at all earns a guess.
		 */
		if (!improvised) {
			if (rep)
				rep->refused = "the image declares no entry "
					       "point";
			kof_emu_free(e);
			return NULL;
		}
		entry = lowest_x ? lowest_x : base_lo;
		improvised = 1;
	}

	if (rep) {
		uint64_t top = cfg.bits == 32 ? STACK_TOP_32 : STACK_TOP;

		rep->stack_hi = top;
		rep->stack_lo = top - (uint64_t)STACK_PAGES * KOF_EMU_PAGE;
	}
	if (!build_stack_pe(e, cfg.bits)) {
		kof_emu_free(e);
		return NULL;
	}
	kof_emu_set_self(e, file, n);
	kof_emu_set_rip(e, entry);

	/*
	 * The same seeding as the ELF path and for the same family of decoders
	 * that index off whatever register the caller left pointing at them.
	 * RSP and RBP are excluded: build_stack_pe just set them.
	 */
	{
		static const unsigned seed[] = {
			KOF_EMU_RAX, KOF_EMU_RCX, KOF_EMU_RDX, KOF_EMU_RBX,
			KOF_EMU_RSI, KOF_EMU_RDI
		};
		unsigned k;

		for (k = 0; k < sizeof seed / sizeof seed[0]; k++)
			kof_emu_set_reg(e, seed[k], entry);
	}

	{
		enum kof_emu_stop st = kof_emu_run(e);
		uint32_t it = 0, k = 0;
		uint64_t va, len;
		const uint8_t *bytes;

		if (rep) {
			rep->stop = st;
			rep->insn = kof_emu_insn_count(e);
			rep->entry = entry;
			rep->improvised = improvised;
			rep->detail = kof_emu_stop_detail(e);
			/*
			 * A fault at the sentinel is the stub RETURNING, which
			 * is how a PE entry point finishes - see
			 * kof_emu_unp_report.returned. Read off rip rather
			 * than out of `detail`, because a number is a fact and
			 * a message is a sentence somebody may reword.
			 */
			rep->returned = st == KOF_EMU_STOP_FAULT &&
					kof_emu_rip(e) == PE_RET_MAGIC;
			for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes,
							   &len); )
				k++;
			rep->images = k;
			for (it = 0, k = 0;
			     kof_emu_next_written(e, &it, &va, &bytes, &len); )
				k++;
			rep->written = k;
		}
	}
	return e;
}
