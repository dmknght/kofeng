#define _GNU_SOURCE   /* kof_memmem's POSIX branch calls the real memmem */
/*
 * emu_unpack_elf.c - an ELF process image for the emulator, laid out the way Linux would,
 * and the run that fills it.
 * Part of the emulated unpack; see emu_unpack.h for what it is for and
 * emu_unpack_private.h for what the files share.
 */

#include "emu_unpack_private.h"

#define DYN_BIAS      0x555555554000ull

/* Where a file with no usable PT_LOAD gets mapped instead. */
#define FLAT_BASE     0x0000000000400000ull

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
static int build_stack(struct kgenome_emu *e, uint64_t entry, uint64_t phdr_va,
		       uint64_t phent, uint64_t phnum, uint64_t base,
		       unsigned bits)
{
	static const char nm[] = "/tmp/a";
	uint8_t zero[16] = { 0 };
	uint64_t v[32], sp, strv;
	uint64_t top = bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP;
	int k = 0;

	if (!kgenome_emu_map(e, top - (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE,
			 NULL, 0, (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE,
			 KGENOME_EMU_R | KGENOME_EMU_W))
		return 0;

	strv = (top - 16u - sizeof nm) & ~15ull;
	kgenome_emu_map(e, strv, (const uint8_t *)nm, sizeof nm, sizeof nm,
		    KGENOME_EMU_R | KGENOME_EMU_W);
	kgenome_emu_map(e, top - 16u, zero, 8, 16, KGENOME_EMU_R | KGENOME_EMU_W);

	v[k++] = 1;                  /* argc      */
	v[k++] = strv;               /* argv[0]   */
	v[k++] = 0;                  /* argv NULL */
	v[k++] = 0;                  /* envp NULL */
	v[k++] = 3;  v[k++] = phdr_va;     /* AT_PHDR   - an ADDRESS, see below */
	v[k++] = 4;  v[k++] = phent;       /* AT_PHENT  */
	v[k++] = 5;  v[k++] = phnum;       /* AT_PHNUM  */
	v[k++] = 6;  v[k++] = KGENOME_EMU_PAGE;/* AT_PAGESZ */
	v[k++] = 9;  v[k++] = entry;       /* AT_ENTRY  */
	v[k++] = 7;  v[k++] = base;        /* AT_BASE   */
	v[k++] = 11; v[k++] = 0;           /* AT_UID    */
	v[k++] = 0;  v[k++] = 0;           /* AT_NULL   */

	sp = (strv - (uint64_t)k * 8u) & ~15ull;
	if (!kgenome_emu_map(e, sp, (const uint8_t *)v, (uint64_t)k * 8u,
			 (uint64_t)k * 8u, KGENOME_EMU_R | KGENOME_EMU_W))
		return 0;
	kgenome_emu_set_reg(e, KGENOME_EMU_RSP, sp);
	return 1;
}

static unsigned perm_of(uint32_t p)
{
	unsigned r = 0;

	if (p & KGENOME_PERM_R) r |= KGENOME_EMU_R;
	if (p & KGENOME_PERM_W) r |= KGENOME_EMU_W;
	if (p & KGENOME_PERM_X) r |= KGENOME_EMU_X;
	return r ? r : KGENOME_EMU_R;
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
 * So the build is here and the run is in kgenome_emu_unp_run, which is this plus
 * kgenome_emu_run and the harvest. Nothing else moved.
 */
struct kgenome_emu *kgenome_emu_unp_build(const uint8_t *file, uint64_t n,
				  const struct kgenome_elf_info *info,
				  const struct kgenome_budget *bud,
				  struct kgenome_emu_unp_report *rep)
{
	struct kgenome_emu_cfg cfg;
	struct kgenome_emu *e;
	uint64_t bias, entry = 0, phdr_va = 0;
	uint32_t i;
	/*
	 * What the mapping learned, including the ranges holding REAL FILE BYTES,
	 * which is not the same as ranges that are mapped: p_memsz outlives
	 * p_filesz, so a segment contributes zero-filled pages past the content
	 * it actually carries, and a truncated file contributes a great many of
	 * them.
	 */
	struct kgenome_emu_unp_map m;

	if (rep)
		memset(rep, 0, sizeof *rep);
	if (!file || !n || !info || !info->valid)
		return NULL;

	memset(&cfg, 0, sizeof cfg);
	cfg.max_insn = bud ? bud->max_insn : 0;
	cfg.max_pages = bud ? (bud->max_bytes + KGENOME_EMU_PAGE - 1u) / KGENOME_EMU_PAGE : 0;
	/*
	 * The width comes from the FILE, not from a caller's opinion: an ELF32
	 * holds i386 code and an ELF64 holds amd64, and the parser has already
	 * normalised which one this is. Reading it here is what keeps the two
	 * from ever disagreeing.
	 */
	cfg.bits = info->elf_class == KGENOME_ELFCLASS_32 ? 32u : 64u;
	e = kgenome_emu_new(&cfg);
	if (!e)
		return NULL;

	/* ET_DYN is linked at zero and a loader picks the base; ET_EXEC carries
	 * its own addresses and must be left where it says it is. */
	bias = (info->e_type == KGENOME_ELF_DYN && info->min_vaddr == 0) ? DYN_BIAS : 0;

	kgenome_emu_unp_map_init(&m, ~0ull);
	for (i = 0; i < info->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
		const struct kgenome_elf_seg *s = &info->seg[i];
		struct kgenome_emu_unp_extent x;

		if (s->type != KGENOME_EMU_UNP_PT_LOAD_TYPE)
			continue;
		x.va = s->mem_addr + bias;
		x.off = s->file_off;
		x.file_size = s->file_size;
		x.mem_size = s->mem_size;
		x.perm = perm_of(s->perm);
		x.code = kgenome_elf_seg_is_code(s);
		/*
		 * Where code could start in this segment, which is not where the
		 * segment starts. The first PT_LOAD of an ordinary binary begins
		 * at file offset 0, so its first bytes are the ELF header and the
		 * program header table - guessing an entry there means decoding
		 * "\x7fELF" as instructions, which is knowably wrong before it is
		 * tried.
		 */
		x.code_skip = !x.off && info->hdr_claim_len
			      ? (info->hdr_claim_len + 15u) & ~15ull : 0;
		x.skip_past_end = 1;
		if (!kgenome_emu_unp_map_extent(e, &m, file, n, &x))
			continue;
		/*
		 * AT_PHDR is an ADDRESS and a stub reads its own program
		 * headers through it - UPX finds its packed data that way.
		 * Passing the file offset pointed it at an unmapped address
		 * near zero, where it read an all-zero header and unpacked
		 * nothing.
		 */
		if (info->phoff >= x.off && info->phoff < x.off + x.file_size)
			phdr_va = x.va + (info->phoff - x.off);
	}

	if (!m.mapped) {
		uint64_t at = (info->min_vaddr != KGENOME_NA && info->min_vaddr)
			      ? (info->min_vaddr & ~(uint64_t)(KGENOME_EMU_PAGE - 1u))
			      : FLAT_BASE;

		if (!kgenome_emu_unp_map_flat(e, &m, at, file, n)) {
			kgenome_emu_free(e);
			return NULL;
		}
		bias = at;
		if (info->phoff && info->phoff < n)
			phdr_va = at + info->phoff;
	}

	/*
	 * Where to start. The declared entry is used whenever it lands on
	 * something mapped - including when the collector called it unmapped,
	 * because "unmapped" was decided against the header's own segment table
	 * and the flat fallback above has since mapped everything. Only when
	 * there is nothing at that address does this fall back to the first
	 * executable mapping, and that is a guess and is reported as one. See
	 * kgenome_emu_unp_map_entry for the rules.
	 */
	entry = info->entry_addr ? info->entry_addr + (m.mapped ? bias : 0) : 0;
	if (!m.mapped && info->entry_addr && info->entry_addr < n)
		entry = bias + info->entry_addr;   /* flat: treat it as an offset */
	if (!kgenome_emu_unp_map_entry(&m, entry, 1, "the object declares no entry "
				       "point", rep, &entry)) {
		kgenome_emu_free(e);
		return NULL;
	}
	if (!entry) {
		kgenome_emu_free(e);
		return NULL;
	}

	if (rep) {
		uint64_t top = cfg.bits == 32 ? KGENOME_EMU_UNP_STACK_TOP_32 : KGENOME_EMU_UNP_STACK_TOP;

		rep->stack_hi = top;
		rep->stack_lo = top - (uint64_t)KGENOME_EMU_UNP_STACK_PAGES * KGENOME_EMU_PAGE;
	}
	if (!build_stack(e, entry, phdr_va ? phdr_va : m.base_lo,
			 info->phentsize, info->phnum, m.base_lo, cfg.bits)) {
		kgenome_emu_free(e);
		return NULL;
	}
	kgenome_emu_set_self(e, file, n);
	kgenome_emu_set_rip(e, entry);

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
			KGENOME_EMU_RAX, KGENOME_EMU_RCX, KGENOME_EMU_RDX, KGENOME_EMU_RBX,
			KGENOME_EMU_RSI, KGENOME_EMU_RDI
		};
		unsigned k;

		for (k = 0; k < sizeof seed / sizeof seed[0]; k++)
			kgenome_emu_set_reg(e, seed[k], entry);
	}

	/* WHAT THE BUILD KNOWS, published before it returns - the run half is
	 * a separate call now and cannot see these locals. */
	if (rep) {
		rep->entry = entry;
		rep->improvised = m.improvised;
	}
	return e;
}

struct kgenome_emu *kgenome_emu_unp_run(const uint8_t *file, uint64_t n,
				const struct kgenome_elf_info *info,
				const struct kgenome_budget *bud,
				struct kgenome_emu_unp_report *rep)
{
	struct kgenome_emu *e = kgenome_emu_unp_build(file, n, info, bud, rep);

	if (!e)
		return NULL;

	{
		enum kgenome_emu_stop st = kgenome_emu_run(e);
		uint64_t xl = 0, xb = kgenome_emu_exc_scratch(e, &xl);
		uint32_t it = 0, k = 0;
		uint64_t va, len;
		const uint8_t *bytes;

		if (rep) {
			rep->stop = st;
			/* Where the host wrote the exception records, so the
			 * harvest can skip them. See kgenome_emu_unp_report. */
			rep->exc_lo = xb;
			rep->exc_hi = xb ? xb + xl : 0;
			rep->insn = kgenome_emu_insn_count(e);
			/* entry and improvised were set by the build. */
			rep->detail = kgenome_emu_stop_detail(e);
			for (it = 0; kgenome_emu_next_snapshot(e, &it, &va, &bytes,
							   &len); )
				k++;
			rep->images = k;
			for (it = 0, k = 0;
			     kgenome_emu_next_written(e, &it, &va, &bytes, &len); )
				k++;
			rep->written = k;
		}
	}
	return e;
}
