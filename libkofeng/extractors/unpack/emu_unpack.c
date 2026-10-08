#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack.c - see emu_unpack.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../kofcore/kofplatform.h"   /* kof_memmem */
#include "../../kofcore/kofdebug.h"
#include "emu_unpack.h"
#include "../../kofeng.h"

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
/*
 * A MEGABYTE, WHICH IS WHAT WINDOWS GIVES A THREAD.
 *
 * 64 pages - 256 KB - was enough for a Linux packer stub, which pushes a
 * frame or two and gets on with it. A protected PE runs its own loader first,
 * and that is ordinary compiled code with ordinary recursion in it: measured,
 * one stopped writing to 0xfffbeffe, which is two bytes below where 64 pages
 * ended. Nothing about the file was wrong; the stack was.
 *
 * The cost is address space and not memory - pages are committed as they are
 * touched - so the number is the one a real thread gets rather than the
 * smallest that happened to work.
 */
#define STACK_PAGES   256u

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
	return (unsigned)kentropy_hist(hist, total);
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

		if (m > n)
			continue;
		/*
		 * kof_memmem AND NOT A COMPARE PER POSITION.
		 *
		 * This walked every offset of the object and ran a memcmp at
		 * each - a naive O(n*m) substring search over a whole file,
		 * twice. The host already has the right tool: memmem, which is
		 * Two-Way inside glibc and vectorised, and on Windows the KMP
		 * fallback in kofplatform.h. Same answer, same bound, one call.
		 */
		if (kof_memmem(file, (size_t)n, want[w], (size_t)m))
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

/*
 * BUILDING THE IMAGE AND RUNNING IT ARE TWO JOBS, AND A SECOND CALLER WANTED
 * ONLY THE FIRST.
 *
 * The diagnose walk's emulate routine has to set instruction watches BEFORE
 * the first instruction executes - it stops at every syscall, reads the site
 * and chooses what the call returns - and a function that builds and runs in
 * one breath gives it nowhere to do that. The alternative was a second ELF
 * image builder beside this one, which is the thing rule 10 exists to stop.
 *
 * So the build is here and the run is in kof_emu_unp_run, which is this plus
 * kof_emu_run and the harvest. Nothing else moved.
 */
struct kof_emu *kof_emu_unp_build(const uint8_t *file, uint64_t n,
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

	/* WHAT THE BUILD KNOWS, published before it returns - the run half is
	 * a separate call now and cannot see these locals. */
	if (rep) {
		rep->entry = entry;
		rep->improvised = improvised;
	}
	return e;
}

struct kof_emu *kof_emu_unp_run(const uint8_t *file, uint64_t n,
				const struct kof_elf_info *info,
				uint64_t max_insn, uint64_t max_pages,
				struct kof_emu_unp_report *rep)
{
	struct kof_emu *e = kof_emu_unp_build(file, n, info, max_insn,
					      max_pages, rep);

	if (!e)
		return NULL;

	{
		enum kof_emu_stop st = kof_emu_run(e);
		uint64_t xl = 0, xb = kof_emu_exc_scratch(e, &xl);
		uint32_t it = 0, k = 0;
		uint64_t va, len;
		const uint8_t *bytes;

		if (rep) {
			rep->stop = st;
			/* Where the host wrote the exception records, so the
			 * harvest can skip them. See kof_emu_unp_report. */
			rep->exc_lo = xb;
			rep->exc_hi = xb ? xb + xl : 0;
			rep->insn = kof_emu_insn_count(e);
			/* entry and improvised were set by the build. */
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
 * kofemu.h puts it, is that they "are the map of what to implement next".
 */
/*
 * Where the thread block goes. Two numbers rather than one masked down, for
 * the reason STACK_TOP_32 above is two: a 32-bit guest computes with 32 bits,
 * and a base it cannot represent is a base it writes through by truncating.
 * Both are clear of the stack and of any image base a PE declares.
 */
#define TEB_BASE_64   0x000007fff0001000ull
#define TEB_BASE_32   0x7ffe1000ull
#define TEB_SPAN      (4ull * KOF_EMU_PAGE)   /* TEB, PEB, LDR, then the heap */

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
 * AND THE ADDRESS SPACE IS A MEGABYTE OF IT, of which only the pages above
 * hold anything.
 *
 * A guest that has a module base does not stop at the end of what this
 * bothered to write: it walks the image the header describes. Measured, one
 * sample read base+0x20b6c - past sixteen pages, and past nothing, so it
 * faulted. A real kernel32 is about this size, the extra pages are zero, and
 * kof_emu_map takes a mapped span larger than its contents for exactly this.
 */
/* The interpreter needs this number too - see KOF_EMU_WIN_MOD_SPAN. */
#define K32_SPAN       KOF_EMU_WIN_MOD_SPAN

/* How many functions one module image can export. Above the largest module in
 * the interpreter's table with room to grow - see the note where it bites. */
#define K32_MAX_EXPORTS 192u

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
#define HEAP_PAGE_OFF    (3ull * KOF_EMU_PAGE)   /* after TEB, PEB, LDR */

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

static int build_teb_pe(struct kof_emu *e, unsigned bits, uint64_t image_base,
			uint64_t stack_lo, uint64_t stack_hi)
{
	uint8_t page[4u * KOF_EMU_PAGE];
	uint64_t teb = bits == 32u ? TEB_BASE_32 : TEB_BASE_64;
	uint64_t peb = teb + KOF_EMU_PAGE;
	uint64_t ldr = peb + KOF_EMU_PAGE;
	uint8_t *t = page, *p = page + KOF_EMU_PAGE, *l = page + 2u * KOF_EMU_PAGE;
	uint8_t *hp = page + 3u * KOF_EMU_PAGE;
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
	 * kof_emu_win_mod_base lists kernel32 first, which is the order of the
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
		static const unsigned load_order[KOF_EMU_WIN_MOD_COUNT] = {
			KOF_EMU_WIN_MOD_NTDLL, KOF_EMU_WIN_MOD_K32,
			KOF_EMU_WIN_MOD_KBASE,
			KOF_EMU_WIN_MOD_USER32, KOF_EMU_WIN_MOD_ADVAPI32,
			KOF_EMU_WIN_MOD_SHELL32, KOF_EMU_WIN_MOD_SHLWAPI,
			KOF_EMU_WIN_MOD_MSVCRT, KOF_EMU_WIN_MOD_OLE32,
			KOF_EMU_WIN_MOD_WS2
		};
		unsigned esz  = bits == 32u ? 0x40u : 0x70u;
		unsigned dllb = bits == 32u ? 0x18u : 0x30u;
		unsigned szof = bits == 32u ? 0x20u : 0x40u;
		unsigned fulln = bits == 32u ? 0x24u : 0x48u;
		unsigned basen = bits == 32u ? 0x2cu : 0x58u;
		unsigned nptr  = bits == 32u ? 4u : 8u;   /* Buffer within it */
		uint64_t ent[KOF_EMU_WIN_MOD_COUNT + 1u];
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

		for (m = 0; m < KOF_EMU_WIN_MOD_COUNT; m++) {
			unsigned mi = load_order[m];
			uint64_t mb = kof_emu_win_mod_base(mi, bits);
			const char *nm = kof_emu_win_mod_name(mi);
			unsigned off = LDR_ENTRIES_OFF + n_ent * esz;
			unsigned len = (unsigned)strlen(nm), c;

			if (!mb || off + esz > LDR_NAMES_OFF)
				continue;
			if (ni + 2u * (len + 1u) > KOF_EMU_PAGE)
				break;
			for (c = 0; c < len; c++) {
				l[ni + 2u * c]      = (uint8_t)nm[c];
				l[ni + 2u * c + 1u] = 0;
			}
			put_w(l + off + dllb, bits, mb);
			put_w(l + off + szof, bits, K32_SPAN);
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

	if (!kof_emu_map(e, teb, page, sizeof page, TEB_SPAN,
			 KOF_EMU_R | KOF_EMU_W))
		return 0;
	/*
	 * 64-bit Windows addresses the TEB through GS and 32-bit through FS.
	 * The numbers are bddisasm's segment ids, which is what the
	 * interpreter's address arithmetic uses.
	 */
	kof_emu_set_seg_base(e, bits == 32u ? 4u : 5u, teb);
	kof_emu_win_set_heap(e, heap);
	return 1;
}


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
 * kofemu.c recognises the number and does the work - see the Windows
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

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static int build_module_pe(struct kof_emu *e, unsigned bits, unsigned mi)
{
	uint8_t img[K32_PAGES * KOF_EMU_PAGE];
	uint64_t base = kof_emu_win_mod_base(mi, bits);
	unsigned all = kof_emu_win_api_count();
	unsigned mine[K32_MAX_EXPORTS], n = 0;
	unsigned ord[K32_MAX_EXPORTS];
	uint32_t name_rva[K32_MAX_EXPORTS];
	uint8_t *ex, *fns, *nms, *ords, *strs, *stub;
	uint32_t str_rva;
	unsigned i, j, opt, pe;

	if (!base)
		return 0;
	/* The functions this module owns, in the order the table lists them -
	 * which is the order kof_emu_win_api_slot counts in, so the n-th here
	 * is the n-th stub there. */
	{
		/*
		 * KERNELBASE EXPORTS WHAT KERNEL32 DOES, which is the truth
		 * about it: a modern kernel32 is mostly forwarders into
		 * kernelbase, so a resolver that goes looking there for a
		 * kernel32 name is right to. It has its own image - see
		 * KOF_EMU_WIN_MOD_KBASE - so a guest that patches one does not
		 * touch the other; only the LIST is shared.
		 */
		unsigned src = mi == KOF_EMU_WIN_MOD_KBASE
			     ? KOF_EMU_WIN_MOD_K32 : mi;

		for (i = 0; i < all && n < K32_MAX_EXPORTS; i++)
			if (kof_emu_win_api_mod(i) == src)
				mine[n++] = i;
	}
	/*
	 * A CAP THAT BITES IS A MISSING EXPORT, and a missing export is
	 * invisible from the outside: kof_emu_win_addr_of searches the whole
	 * table, so GetProcAddress still answers for a name past the cap and
	 * only a guest WALKING the directory ever notices. Measured, that is
	 * what an MPRESS stub does, and with the cap at 64 against 81 kernel32
	 * entries its search ran off the end of the list and resolved to zero.
	 */
	if (n == K32_MAX_EXPORTS)
		KOF_TRACE("[mod] %s: export list capped at %u\n",
			kof_emu_win_mod_name(mi), n);
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
		const char *mn = kof_emu_win_mod_name(mi);
		unsigned len = (unsigned)strlen(mn) + 1u;

		memcpy(strs, mn, len);
		put32(ex + 12u, str_rva);
		strs += len;
		str_rva += len;
	}

	for (i = 0; i < n; i++) {
		const char *nm = kof_emu_win_api_name(mine[i]);
		unsigned len = (unsigned)strlen(nm) + 1u;

		memcpy(strs, nm, len);
		name_rva[i] = str_rva;
		strs += len;
		str_rva += len;
		put32(fns + 4u * i,
		      (uint32_t)(K32_STUB_RVA + i * KOF_EMU_WIN_STUB));
		ord[i] = i;
	}

	/* Sort the NAME array - the function array stays in ordinal order and
	 * the ordinal array is what ties the two together. */
	for (i = 1; i < n; i++) {
		unsigned k = ord[i];

		for (j = i; j > 0 &&
		     strcmp(kof_emu_win_api_name(mine[ord[j - 1]]),
			    kof_emu_win_api_name(mine[k])) > 0; j--)
			ord[j] = ord[j - 1];
		ord[j] = k;
	}
	for (i = 0; i < n; i++) {
		put32(nms + 4u * i, name_rva[ord[i]]);
		put16(ords + 2u * i, (uint16_t)ord[i]);
	}

	put32(ex + 16u, 1u);                    /* Base: ordinals start at 1 */
	put32(ex + 20u, n);                     /* NumberOfFunctions */
	put32(ex + 24u, n);                     /* NumberOfNames */
	put32(ex + 28u, (uint32_t)(fns - img));
	put32(ex + 32u, (uint32_t)(nms - img));
	put32(ex + 36u, (uint32_t)(ords - img));

	/* ---- the stubs ---- */
	stub = img + K32_STUB_RVA;
	for (i = 0; i < n; i++) {
		uint8_t *p = stub + i * KOF_EMU_WIN_STUB;
		unsigned argc = kof_emu_win_api_argc(mine[i]);

		p[0] = 0xb8;                            /* mov eax, imm32 */
		put32(p + 1, kof_emu_win_api_trap(mine[i]));
		if (bits == 32u) {
			p[5] = 0xcd; p[6] = 0x80;       /* int 0x80 */
			if (argc) {
				p[7] = 0xc2;            /* ret argc*4 */
				put16(p + 8, (uint16_t)(argc * 4u));
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
	put32(img + 0x3cu, pe);
	img[pe] = 'P'; img[pe + 1] = 'E';
	put16(img + pe + 4u, bits == 32u ? 0x014cu : 0x8664u);
	put16(img + pe + 6u, 1u);                       /* one section */
	opt = bits == 32u ? 224u : 240u;
	put16(img + pe + 20u, (uint16_t)opt);
	put16(img + pe + 22u, 0x2102u);                 /* DLL | EXECUTABLE */

	{
		uint8_t *o = img + pe + 24u;
		unsigned dd;

		put16(o, bits == 32u ? 0x010bu : 0x020bu);
		if (bits == 32u) {
			put32(o + 28u, (uint32_t)base);         /* ImageBase */
			dd = 96u;
			put32(o + 92u, 16u);                    /* NumberOfRvaAndSizes */
		} else {
			put32(o + 24u, (uint32_t)base);
			put32(o + 28u, (uint32_t)(base >> 32));
			dd = 112u;
			put32(o + 108u, 16u);
		}
		put32(o + 32u, KOF_EMU_PAGE);                   /* SectionAlignment */
		put32(o + 36u, 0x200u);                         /* FileAlignment */
		put32(o + 56u, K32_SPAN);                       /* SizeOfImage */
		put32(o + 60u, KOF_EMU_PAGE);                   /* SizeOfHeaders */
		put32(o + dd, K32_EXPORT_RVA);
		put32(o + dd + 4u, (uint32_t)(str_rva - K32_EXPORT_RVA));

		{
			uint8_t *sec = o + opt;

			/* One section from the stubs to the end of the image,
			 * so both the code and the export directory are inside
			 * something the section table accounts for. */
			memcpy(sec, ".text", 6u);
			put32(sec + 8u, K32_SPAN - K32_STUB_RVA);
			put32(sec + 12u, K32_STUB_RVA);         /* VirtualAddress */
			put32(sec + 16u, K32_SPAN - K32_STUB_RVA);
			put32(sec + 20u, K32_STUB_RVA);         /* PointerToRawData */
			put32(sec + 36u, 0x60000020u);          /* CODE|EXEC|READ */
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
	if (!kof_emu_map(e, base, img, K32_STUB_RVA, K32_STUB_RVA, KOF_EMU_R))
		return 0;
	if (!kof_emu_map(e, base + K32_STUB_RVA, img + K32_STUB_RVA,
			 sizeof img - K32_STUB_RVA, K32_SPAN - K32_STUB_RVA,
			 KOF_EMU_R | KOF_EMU_X))
		return 0;
	kof_emu_win_set_module(e, mi, base);
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
static uint64_t rva_to_off(const struct kof_pe_info *info, uint64_t rva,
			   uint64_t n)
{
	uint32_t i;

	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &info->sec[i];
		uint64_t span = s->mem_size > s->file_size ? s->mem_size
							   : s->file_size;

		if (rva < s->mem_rva || rva >= s->mem_rva + span)
			continue;
		if (rva - s->mem_rva >= s->file_size)
			return 0;               /* in the zero fill */
		if (s->file_off + (rva - s->mem_rva) >= n)
			return 0;
		return s->file_off + (rva - s->mem_rva);
	}
	return 0;
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static unsigned fill_iat_pe(struct kof_emu *e, const struct kof_pe_info *info,
			    const uint8_t *file, uint64_t n, uint64_t base,
			    unsigned bits)
{
	uint64_t dir = info->dir[KOF_PE_DIR_IMPORT].rva;
	uint64_t at, w = bits == 32u ? 4u : 8u;
	unsigned filled = 0, seen = 0, d;

	if (!dir)
		return 0;
	at = rva_to_off(info, dir, n);
	if (!at)
		return 0;

	/*
	 * TWO BOUNDS AND NOT ONE. Sixty-four descriptors each with four
	 * thousand thunks is a quarter of a million rva_to_off calls, and
	 * rva_to_off walks the section table - so a file that declares both
	 * maxima costs twenty-five million operations before a single guest
	 * instruction runs. `filled` is not that bound because a crafted table
	 * fills nothing; `seen` counts the work rather than the result.
	 */
	for (d = 0; d < 64u && seen < 8192u; d++) {
		uint64_t desc = at + (uint64_t)d * 20u;
		uint64_t oft, ft, thunk, name_tab;
		unsigned k;

		if (desc + 20u > n)
			break;
		oft = rd32(file + desc);
		ft  = rd32(file + desc + 16u);
		if (!oft && !ft)
			break;                  /* the terminating descriptor */
		name_tab = oft ? oft : ft;      /* the hint/name array */
		if (!ft)
			continue;

		for (k = 0; k < 4096u && seen < 8192u; k++, seen++) {
			uint64_t nt_off = rva_to_off(info, name_tab + k * w, n);
			uint64_t val, hint_rva, hint_off, addr;
			char nm[128];
			unsigned c;

			if (!nt_off || nt_off + w > n)
				break;
			val = bits == 32u ? rd32(file + nt_off)
					  : (uint64_t)rd32(file + nt_off) |
					    ((uint64_t)rd32(file + nt_off + 4u) << 32);
			if (!val)
				break;              /* end of this table */
			if (val & (bits == 32u ? 0x80000000ull
					       : 0x8000000000000000ull))
				continue;           /* by ordinal, not by name */

			hint_rva = (val & 0x7fffffffu) + 2u;   /* past the hint */
			hint_off = rva_to_off(info, hint_rva, n);
			if (!hint_off)
				continue;
			for (c = 0; c + 1u < sizeof nm &&
				    hint_off + c < n && file[hint_off + c]; c++)
				nm[c] = (char)file[hint_off + c];
			nm[c] = 0;

			addr = kof_emu_win_addr_of(e, nm);
			if (!addr) {
				/* Which name the environment does not have is
				 * the only thing that says what to add to it:
				 * an unfilled thunk and a thunk nobody asked
				 * about are the same zero. */
				KOF_TRACE("[iat] miss %s\n", nm);
				continue;
			}
			thunk = base + ft + (uint64_t)k * w;
			if (kof_emu_write(e, thunk, &addr, (unsigned)w))
				filled++;
		}
	}
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
 * ---- RUNNING ON WHILE THE RUN IS STILL PRODUCING --------------------------
 *
 * The budget is a guess and it is wrong in both directions - see
 * kof_emu_set_max_insn for the measurement that prompted this: a PECompact2
 * sample reached the ceiling having decompressed 6.5 of the 8.6 megabytes its
 * own header declares, stopped two thirds of the way through something that
 * was working.
 *
 * THREE BOUNDS, AND THE FIRST ONE ALONE MAKES A LOOP IMPOSSIBLE.
 *
 *   1. AT MOST EMU_EXTEND_MAX EXTENSIONS. A count, not a condition. Whatever
 *      the guest does, this returns after at most that many more slices - so
 *      no behaviour, crafted or otherwise, can keep it here.
 *   2. PROGRESS MUST HAVE ADVANCED. Not "recently" but STRICTLY since the last
 *      grant: kof_emu_last_write is the instruction at which a page was first
 *      written, and a slice that did not raise it wrote nothing new. A guest
 *      writing one fresh page per slice still only gets EMU_EXTEND_MAX of them.
 *   3. A TOTAL CEILING, so the sum is bounded in absolute terms and not only
 *      as a multiple of an object's size.
 *
 * MEMORY IS NOT EXTENDED. max_pages and the snapshot budget are set once, so a
 * long run holds no more than a short one; what grows is time, and time is
 * what bounds 1 and 3 are for.
 */
#define EMU_EXTEND_MAX   8u
#define EMU_EXTEND_TOTAL (2048ull << 20)   /* the sum of every slice */


static enum kof_emu_stop emu_run_while_producing(struct kof_emu *e,
						 uint64_t slice, int hand_back)
{
	enum kof_emu_stop st;
	unsigned k = 0;

	for (;;) {
		/*
		 * READ BEFORE THE SLICE, NOT AFTER. The first version of this
		 * took the mark after the run and compared it with itself, so
		 * the test was always "unchanged" and no extension was ever
		 * granted - the code was there and did nothing. What the test
		 * has to ask is whether THIS slice wrote a page it had never
		 * written before.
		 */
		uint64_t before = kof_emu_last_write(e);
		uint64_t next;

		st = kof_emu_run(e);
		if (st != KOF_EMU_STOP_BUDGET || !slice)
			break;
		/* A module asked to be shown each slice - see `hand_back`. */
		if (hand_back)
			break;
		{
			if (k >= EMU_EXTEND_MAX)
				break;          /* the count, which bounds this */
			if (kof_emu_last_write(e) <= before)
				break;          /* the slice produced nothing */
		}
		next = kof_emu_insn_count(e) + slice;
		if (next > EMU_EXTEND_TOTAL)
			break;                  /* the absolute ceiling */
		/* Keep what this slice earned before risking the next one -
		 * see kof_emu_snap_written. */
		kof_emu_snap_written(e);
		kof_emu_set_max_insn(e, next);
		k++;
	}
	return st;
}

/* ---- putting a run's sections back into a file ---------------------------
 * See kof_pe_image_from_run in the header for what this selects and why.
 */
static void pir_put16(uint8_t *p, unsigned v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void pir_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

int kof_pe_image_from_run(struct kof_emu *e, const struct kof_pe_info *info,
			  uint64_t base, uint64_t cap,
			  uint8_t **out, uint64_t *out_len)
{
	uint64_t hdr = 0, total = 0, va, len;
	const uint8_t *bytes;
	uint8_t *b, *o, *sec;
	uint32_t i, it, placed = 0;
	unsigned pe_off = 0x80u, opt, nrva, sec_at;
	uint64_t oep = 0, oep_rva = 0;
	struct { uint64_t rva, len; } ach[KOF_PE_RUN_CHUNKS];
	unsigned n_ach = 0;

	if (!e || !info || !info->valid || !info->sec_count || !out || !out_len)
		return 0;

	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &info->sec[i];
		uint64_t end = (s->mem_rva + s->mem_size + KOF_EMU_PAGE - 1u) &
			       ~(uint64_t)(KOF_EMU_PAGE - 1u);

		if (!hdr || s->mem_rva < hdr)
			hdr = s->mem_rva;
		if (end > total)
			total = end;
	}
	if (hdr < KOF_EMU_PAGE)
		hdr = KOF_EMU_PAGE;
	hdr &= ~(uint64_t)(KOF_EMU_PAGE - 1u);

	/*
	 * MEMORY THE RUN ALLOCATED IS PART OF THE IMAGE, as a section of its
	 * own. Unipacker's imagedump.py does exactly this - chunk_to_image_
	 * section_hdr names them .ach0, .ach1 ... and gives each the chunk's
	 * address as both VirtualAddress and PointerToRawData - and its
	 * dump_image takes SizeOfImage from the highest chunk rather than from
	 * the section table. See THIRD-PARTY.md.
	 *
	 * BOUNDED BY cap, WHICH UNIPACKER DOES NOT DO. A stub that allocates at
	 * 0x20000000 from a base of 0x400000 describes an image half a gigabyte
	 * long, nearly all of it a hole - measured, that is what a PECompact2
	 * sample does. Such a chunk is left out here and still comes back on
	 * its own, as one of the regions the snapshot loop hands over: the
	 * bytes are never lost, they just do not get a section header.
	 */
	for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		uint64_t rva, end;
		int is_sec = 0;

		if (va < base || !len)
			continue;
		rva = va - base;
		for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++)
			if (rva == info->sec[i].mem_rva) {
				is_sec = 1;
				break;
			}
		if (is_sec || rva < total)
			continue;
		end = (rva + len + KOF_EMU_PAGE - 1u) &
		      ~(uint64_t)(KOF_EMU_PAGE - 1u);
		if (end > cap)
			continue;
		if (n_ach >= KOF_PE_RUN_CHUNKS)
			break;
		ach[n_ach].rva = rva;
		ach[n_ach].len = len;
		n_ach++;
		if (end > total)
			total = end;
	}

	opt = info->pe32_plus ? 0xf0u : 0xe0u;
	nrva = info->pe32_plus ? 108u : 92u;
	sec_at = pe_off + 24u + opt;
	if (!total || total > cap ||
	    sec_at + 40u * (info->sec_count + n_ach) > hdr)
		return 0;

	b = calloc(1, (size_t)total);
	if (!b)
		return 0;

	/*
	 * THE SECTIONS, READ STRAIGHT OUT OF GUEST MEMORY.
	 *
	 * Not from the snapshot set, which is memory the run made executable.
	 * A stub that decrypts INTO pages that were already executable - which
	 * is what a packed image's own sections are - never calls mprotect and
	 * so takes no snapshot, and measured on an MPRESS sample the whole
	 * snapshot set was twelve kilobytes of scratch while the decrypted
	 * program sat in the image where it had always been.
	 *
	 * Unipacker's imagedump.py does exactly this: `pe_write(uc, base_addr,
	 * total_size, path)` reads the image range out of the emulator. See
	 * THIRD-PARTY.md. The snapshot pass below still runs, for a section the
	 * guest relocated somewhere else.
	 */
	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *sc = &info->sec[i];
		uint64_t n = sc->mem_size, at;

		if (!n || sc->mem_rva >= total)
			continue;
		if (n > total - sc->mem_rva)
			n = total - sc->mem_rva;
		for (at = 0; at < n; at += KOF_EMU_PAGE) {
			uint64_t k = n - at < KOF_EMU_PAGE ? n - at : KOF_EMU_PAGE;

			/* A page at a time, because an image may be mapped
			 * with holes and one unreadable page must not lose
			 * the rest of the section. */
			if (kof_emu_read(e, base + sc->mem_rva + at,
					 b + sc->mem_rva + at, (unsigned)k))
				placed++;
		}
	}

	/* The regions that ARE sections, each at its own address. */
	for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		if (va < base)
			continue;
		for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
			const struct kof_pe_sec *s = &info->sec[i];
			uint64_t rva = va - base, n = len;

			if (rva != s->mem_rva)
				continue;
			if (rva >= total)
				break;
			if (n > total - rva)
				n = total - rva;
			memcpy(b + rva, bytes, (size_t)n);
			placed++;
			break;
		}
	}
	for (it = 0; kof_emu_next_snapshot(e, &it, &va, &bytes, &len); ) {
		for (i = 0; i < n_ach; i++) {
			uint64_t n = len;

			if (va < base || va - base != ach[i].rva)
				continue;
			if (n > total - ach[i].rva)
				n = total - ach[i].rva;
			memcpy(b + ach[i].rva, bytes, (size_t)n);
			placed++;
			break;
		}
	}
	if (!placed) {
		free(b);
		return 0;
	}

	b[0] = 'M'; b[1] = 'Z';
	pir_put32(b + 0x3c, pe_off);
	b[pe_off] = 'P'; b[pe_off + 1] = 'E';
	pir_put16(b + pe_off + 4u, info->machine);
	pir_put16(b + pe_off + 6u, (unsigned)info->sec_count + n_ach);
	pir_put16(b + pe_off + 20u, opt);
	pir_put16(b + pe_off + 22u, info->pe32_plus ? 0x0022u : 0x0102u);

	o = b + pe_off + 24u;
	pir_put16(o, info->pe32_plus ? 0x020bu : 0x010bu);
	/*
	 * THE ENTRY POINT IS WHERE THE RUN FIRST LEFT THE STUB, not the entry
	 * point in the file - that one is the stub's. Both Unipacker
	 * (imagedump.py: AddressOfEntryPoint = EIP at dump time) and Unlicense
	 * (dump_pe's oep argument) write the dumped address, and section
	 * hopping is where Unipacker takes it. See THIRD-PARTY.md.
	 *
	 * If the run never hopped, nothing here knows the original entry, and 0
	 * says exactly that rather than pointing at the stub.
	 */
	{
		uint64_t last = 0;
		uint32_t hops = 0;

		kof_emu_first_hop(e, NULL, &oep);
		kof_emu_last_hop(e, &last, &hops);
		if (last >= base && last - base < total)
			oep = last;
		KOF_TRACE("[oep] hops=%u first=%#llx last=%#llx\n",
				hops, (unsigned long long)oep,
				(unsigned long long)last);
	}
	if (oep >= base && oep - base < total)
		oep_rva = oep - base;
	pir_put32(o + 16u, (uint32_t)oep_rva);
	pir_put32(o + 20u, (uint32_t)hdr);
	if (info->pe32_plus) {
		pir_put32(o + 24u, (uint32_t)info->image_base);
		pir_put32(o + 28u, (uint32_t)(info->image_base >> 32));
	} else {
		pir_put32(o + 28u, (uint32_t)info->image_base);
	}
	pir_put32(o + 32u, KOF_EMU_PAGE);
	pir_put32(o + 36u, KOF_EMU_PAGE);
	pir_put16(o + 40u, 6u);
	pir_put16(o + 48u, 6u);
	pir_put32(o + 56u, (uint32_t)total);
	pir_put32(o + 60u, (uint32_t)hdr);
	pir_put16(o + 68u, info->subsystem);
	pir_put32(o + nrva, 16u);

	sec = b + sec_at;
	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &info->sec[i];
		uint64_t span = (s->mem_size + KOF_EMU_PAGE - 1u) &
				~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint8_t *d = sec + 40u * i;
		unsigned k;

		for (k = 0; k < 8u; k++)
			d[k] = (uint8_t)s->name[k];
		pir_put32(d + 8u,  (uint32_t)s->mem_size);
		pir_put32(d + 12u, (uint32_t)s->mem_rva);
		pir_put32(d + 16u, (uint32_t)span);
		pir_put32(d + 20u, (uint32_t)s->mem_rva);
		pir_put32(d + 36u, s->characteristics | 0x40000000u);
	}
	for (i = 0; i < n_ach; i++) {
		uint64_t span = (ach[i].len + KOF_EMU_PAGE - 1u) &
				~(uint64_t)(KOF_EMU_PAGE - 1u);
		uint8_t *d = sec + 40u * (info->sec_count + i);

		memcpy(d, ".ach", 4);
		d[4] = (uint8_t)('0' + (i % 10u));
		pir_put32(d + 8u,  (uint32_t)ach[i].len);
		pir_put32(d + 12u, (uint32_t)ach[i].rva);
		pir_put32(d + 16u, (uint32_t)span);
		pir_put32(d + 20u, (uint32_t)ach[i].rva);
		pir_put32(d + 36u, 0xe0000020u);
	}

	*out = b;
	*out_len = total;
	return 1;
}
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

/*
 * The image with the declared patches applied, as a private copy - or NULL when
 * there is nothing to apply or no memory for a copy, in which case the run goes
 * ahead on the unpatched bytes rather than not at all. Every occurrence inside
 * a section's file bytes is replaced (a pattern that matches twice is two
 * places the same check lives), in section order, and a pattern is looked for
 * only INSIDE a section: a match straddling two is not code.
 */
static uint8_t *apply_patches(const uint8_t *file, uint64_t n,
			      const struct kof_pe_info *info,
			      const struct kof_emu_decl *decl)
{
	uint8_t *c = malloc((size_t)n);
	uint32_t k, i;
	int hit = 0;

	if (!c)
		return NULL;
	memcpy(c, file, (size_t)n);
	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &info->sec[i];
		uint64_t off = s->file_off, len = s->file_size, at;

		if (off >= n)
			continue;
		if (len > n - off)
			len = n - off;
		for (k = 0; k < decl->n_patch && k < KOF_EMU_PATCH_MAX; k++) {
			const struct kof_emu_patch *p = &decl->patch[k];

			if (!p->n || p->n > KOF_EMU_PATCH_LEN || len < p->n)
				continue;
			for (at = 0; at + p->n <= len; at++)
				if (c[off + at] == p->find[0] &&
				    !memcmp(c + off + at, p->find, p->n)) {
					memcpy(c + off + at, p->rep, p->n);
					at += p->n - 1u;
					hit = 1;
				}
		}
	}
	if (!hit) {
		free(c);
		return NULL;
	}
	return c;
}

struct kof_emu *kof_emu_unp_run_pe(const uint8_t *file, uint64_t n,
				   const struct kof_pe_info *info,
				   uint64_t max_insn, uint64_t max_pages,
				   uint64_t idle, int hand_back,
				   const struct kof_emu_oep *oep,
				   unsigned n_oep,
				   const struct kof_emu_decl *decl,
				   struct kof_emu_unp_report *rep)
{
	struct kof_emu_cfg cfg;
	uint8_t *patched = NULL;
	const uint8_t *img;
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

	img = file;
	if (decl && decl->n_patch) {
		patched = apply_patches(file, n, info, decl);
		if (patched)
			img = patched;
	}

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

		if (kof_emu_map(e, base, img, hl, hl, KOF_EMU_R)) {
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
		/*
		 * EXECUTABLE WHATEVER THE SECTION SAYS.
		 *
		 * A section's characteristics describe what the LOADER sets,
		 * and a packed image's stub changes it the moment it runs -
		 * every one of them calls VirtualProtect on the section it
		 * decompresses into. Enforcing the file's word about it buys
		 * nothing and costs runs: measured, a VMProtect stub jumps
		 * from its entry point into a section this engine had
		 * reconstructed as data, and the run ended there after 22
		 * instructions. The section flags of a REBUILT image are a
		 * reconstruction anyway - they are this engine's guess about
		 * content, not the original loader's word about permission.
		 *
		 * The execute check in the interpreter is still worth having,
		 * and still fires where it was written for: the fabricated
		 * library images, whose headers a guest reaches only by
		 * resolving an export this build does not have.
		 */
		if (!kof_emu_map(e, va, fsz ? img + off : NULL, fsz, msz,
				 perm_of_pe(s->perm) | KOF_EMU_X))
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
		if (!kof_emu_map(e, base, img, n, n,
				 KOF_EMU_R | KOF_EMU_W | KOF_EMU_X)) {
			free(patched);
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

	/* The pages own their bytes now; the patched copy has done its job. */
	free(patched);
	patched = NULL;

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
	/*
	 * AND THE THREAD BLOCK, which the stack alone is not. See build_teb_pe
	 * for the measurement that says this belongs here; a failure to map it
	 * is a failure of the run, because a guest that reads gs:[0x30] against
	 * a base of zero faults on data the host chose not to provide rather
	 * than on anything the file did.
	 */
	if (!build_teb_pe(e, cfg.bits, base,
			  (cfg.bits == 32 ? STACK_TOP_32 : STACK_TOP) -
			  (uint64_t)STACK_PAGES * KOF_EMU_PAGE,
			  cfg.bits == 32 ? STACK_TOP_32 : STACK_TOP)) {
		kof_emu_free(e);
		return NULL;
	}
	/*
	 * AND THE ONE LIBRARY, AND THE THUNKS THAT POINT INTO IT.
	 *
	 * In that order, because the thunks are filled with addresses inside
	 * the image the line above maps. Neither is fatal to skip - a guest
	 * that never asks for kernel32 never notices either - but a failure
	 * here means the host could not map two pages, and a run under that
	 * much memory pressure is not one worth starting.
	 */
	{
		unsigned mi;

		kof_emu_win_setup(e, base);
		/*
		 * kernel32 must map or the run is pointless - it is what every
		 * stub asks for. The rest are best effort: a library that
		 * could not be mapped is one the guest is told it does not
		 * have, which is a true answer and a visible one.
		 */
		for (mi = 0; mi < kof_emu_win_mod_count(); mi++)
			if (!build_module_pe(e, cfg.bits, mi) &&
			    mi == KOF_EMU_WIN_MOD_K32) {
				kof_emu_free(e);
				return NULL;
			}
		{
			unsigned nf = fill_iat_pe(e, info, file, n, base,
						  cfg.bits);

			KOF_TRACE("[emu] iat filled=%u dir=%#llx\n", nf,
					(unsigned long long)
					info->dir[KOF_PE_DIR_IMPORT].rva);
		}
	}
	/*
	 * AND WHERE THE PROGRAM WILL BE WHEN THE LOADER IS DONE.
	 *
	 * A section with a VirtualSize and no SizeOfRawData is a region the
	 * file declares and does not supply - so nothing but the run can put
	 * code in it, and a fetch from one is the loader handing over. See
	 * kof_emu_watch_exec, which carries the argument and the attribution
	 * for where the idea came from.
	 *
	 * NOT THE SECTION THE ENTRY POINT IS IN, even when that one is hollow
	 * too: the run starts there, so watching it would stop on the first
	 * instruction.
	 */
	/*
	 * ONLY WHEN THE HOLLOW SECTIONS ARE THE PROGRAM, which is not every
	 * file that has one.
	 *
	 * The shape this is for puts the whole image inside the section the
	 * entry point is in and leaves the originals with a size and no bytes:
	 * then a fetch from one of them is the loader handing over. The other
	 * shape - SecureEngine's - is the reverse. Its `.themida` is the
	 * hollow one and it holds the LOADER, while the program sits in the
	 * sections that do have bytes, encrypted. Watching hollow sections
	 * there stops the run on the loader's first instruction, which is the
	 * opposite of the intent.
	 *
	 * The discriminator is where the file's raw bytes are: in the first
	 * shape the entry section holds almost all of them, in the second it
	 * does not. That is the same test bases/unp/hollow_pe.c is built on.
	 */
	/*
	 * WHAT THE MODULE SAID, FIRST, because it knows the container and this
	 * file does not. The structural rule below is the fallback for an
	 * object no module spoke for.
	 */
	for (i = 0; i < n_oep; i++)
		if (oep[i].len) {
			kof_emu_watch_exec(e, base + oep[i].rva,
					   base + oep[i].rva + oep[i].len);
			/*
			 * AND THE SAME RANGES WATCHED FOR WRITES.
			 *
			 * A module naming these is saying "the program will be
			 * here", and for a protector that means two different
			 * things at two different times: the loader DECRYPTS
			 * into them and only then JUMPS into them. The exec
			 * watch catches the jump; this catches the decryption,
			 * which happens first and happens even when the jump
			 * never does. See kof_emu_watch_write.
			 */
			kof_emu_watch_write(e, base + oep[i].rva,
					    base + oep[i].rva + oep[i].len);
		}

	if (!n_oep)
	{
		uint64_t raw_other = 0, raw_entry = 0;

		for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
			if (i == info->entry_sec)
				raw_entry = info->sec[i].file_size;
			else
				raw_other += info->sec[i].file_size;
		}
		if (raw_entry && raw_other * 20u <= raw_entry)
			for (i = 0; i < info->sec_count &&
				    i < KOF_PE_MAX_SECTIONS; i++) {
				const struct kof_pe_sec *s = &info->sec[i];

				if (i == info->entry_sec || s->file_size ||
				    !s->mem_size)
					continue;
				kof_emu_watch_exec(e, base + s->mem_rva,
						   base + s->mem_rva +
						   s->mem_size);
			}
	}
	kof_emu_set_self(e, file, n);
	if (idle)
		kof_emu_set_idle(e, idle);
	kof_emu_count_mod_reads(e, 1);
	/* The stub's own section, so a jump it makes inside itself is not read
	 * as a handover - see kof_emu_set_stub_range. */
	if (info->entry_sec < info->sec_count) {
		const struct kof_pe_sec *es = &info->sec[info->entry_sec];

		kof_emu_set_stub_range(e, base + es->mem_rva,
				       base + es->mem_rva + es->mem_size);
	}
	/* And the image itself, so the run can dump it at the handover rather
	 * than at its end - see the write-then-execute snapshot in kofemu. */
	{
		uint64_t hi = 0;
		uint32_t si;

		for (si = 0; si < info->sec_count &&
			     si < KOF_PE_MAX_SECTIONS; si++) {
			uint64_t end = info->sec[si].mem_rva +
				       info->sec[si].mem_size;

			if (end > hi)
				hi = end;
		}
		if (hi) {
			kof_emu_set_image_range(e, base, base + hi);
			/* And the handover test, which needs that range - see
			 * kof_emu_set_oep_watch. */
			kof_emu_set_oep_watch(e, 1);
		}
	}
	{
		uint64_t top = cfg.bits == 32 ? STACK_TOP_32 : STACK_TOP;

		kof_emu_set_stack_range(e,
			top - (uint64_t)STACK_PAGES * KOF_EMU_PAGE, top);
	}
	/*
	 * EVERY SECTION IS A STAGE TO WATCH, and the entry point's is marked
	 * as already seen because the run begins in it. See kof_emu_hop_add.
	 */
	for (i = 0; i < info->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *hs = &info->sec[i];

		if (!hs->mem_size)
			continue;
		kof_emu_hop_add(e, base + hs->mem_rva,
				base + hs->mem_rva + hs->mem_size,
				i == info->entry_sec);
	}
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

	/*
	 * AND WHAT A MODULE ASKED TO BE PAUSED ON, set last so that everything
	 * the setup does is behind it - see kof_emu_watch_insn.
	 */
	{
		unsigned k;

		if (decl) {
			for (k = 0; k < decl->n_iw; k++)
				kof_emu_watch_insn(e, decl->iw[k].b,
						   decl->iw[k].n);
			if (decl->n_iw)
				kof_emu_watch_insn_len(e, decl->iw_len);
			for (k = 0; k < decl->n_shim; k++)
				(void)kof_emu_shim_api(e, decl->shim[k].name,
						       decl->shim[k].ret);
		}
	}

	{
		enum kof_emu_stop st = emu_run_while_producing(e, max_insn, hand_back);
		uint64_t xl = 0, xb = kof_emu_exc_scratch(e, &xl);
		uint32_t it = 0, k = 0;
		uint64_t va, len;
		const uint8_t *bytes;

		if (rep) {
			rep->stop = st;
			/* Where the host wrote the exception records, so the
			 * harvest can skip them. See kof_emu_unp_report. */
			rep->exc_lo = xb;
			rep->exc_hi = xb ? xb + xl : 0;
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
