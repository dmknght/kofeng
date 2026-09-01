/*
 * emu_unpack.c - see emu_unpack.h.
 */

#include <stdlib.h>
#include <string.h>

#include "emu_unpack.h"

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
	uint64_t acc = 0;
	unsigned i;

	if (!total)
		return 0;
	for (i = 0; i < 256u; i++) {
		uint64_t n = hist[i], scaled;
		unsigned lg = 0;

		if (!n)
			continue;
		/*
		 * -log2(n/total) = log2(total) - log2(n), computed on
		 * total*256/n so the fraction survives the integer log.
		 */
		scaled = (total << 8) / n;
		while (scaled >> (lg + 1u))
			lg++;
		/* lg is floor(log2()); the remainder interpolates linearly
		 * between it and the next power, which is accurate to well
		 * under the eighth of a bit this is measured in. */
		{
			uint64_t base = (uint64_t)1 << lg;
			uint64_t frac = ((scaled - base) << 3) / base;

			acc += n * (((uint64_t)lg << 3) + frac - (8u << 3));
		}
	}
	return (unsigned)(acc / total);
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
	 * x86-64 only, and that is measurement rather than caution: every one
	 * of the 294 dense objects in the clean-corpus run was x86-64, and
	 * bddisasm decodes x86 alone. An ARM object would be started here and
	 * stopped on its first instruction, which costs a page table and
	 * teaches nothing.
	 */
	if (ctx->arch != KOF_ARCH_X86_64)
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
		       uint64_t phent, uint64_t phnum, uint64_t base)
{
	static const char nm[] = "/tmp/a";
	uint8_t zero[16] = { 0 };
	uint64_t v[32], sp, strv;
	int k = 0;

	if (!kof_emu_map(e, STACK_TOP - (uint64_t)STACK_PAGES * KOF_EMU_PAGE,
			 NULL, 0, (uint64_t)STACK_PAGES * KOF_EMU_PAGE,
			 KOF_EMU_R | KOF_EMU_W))
		return 0;

	strv = (STACK_TOP - 16u - sizeof nm) & ~15ull;
	kof_emu_map(e, strv, (const uint8_t *)nm, sizeof nm, sizeof nm,
		    KOF_EMU_R | KOF_EMU_W);
	kof_emu_map(e, STACK_TOP - 16u, zero, 8, 16, KOF_EMU_R | KOF_EMU_W);

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

	if (!build_stack(e, entry, phdr_va ? phdr_va : base_lo,
			 info->phentsize, info->phnum, base_lo)) {
		kof_emu_free(e);
		return NULL;
	}
	kof_emu_set_self(e, file, n);
	kof_emu_set_rip(e, entry);

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
