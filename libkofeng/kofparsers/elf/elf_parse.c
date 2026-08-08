/*
 * elf_parse.c - ELF header, program header and section header collector.
 *
 * Segments are read before sections and treated as authoritative. That is not
 * an ordering convenience: the kernel loader needs only the program headers, so
 * an object whose section table has been stripped or forged still runs. Any
 * reasoning about what executes should come from segments, with section
 * disagreement reported as signal rather than resolved silently.
 *
 * Two rules hold throughout:
 *
 *   - never fail, always describe. A malformed field produces an anomaly bit,
 *     not an early return. Refusing would go blind on exactly the inputs worth
 *     looking at, and the malformation is itself evidence.
 *
 *   - every read goes through kofcore. No pointer arithmetic, no local bounds
 *     checks, and no count taken from the file is trusted before it is clamped.
 */

#include "elf_parse.h"

#include <string.h>

/* e_ident indices */
#define EI_MAG0		0
#define EI_CLASS	4
#define EI_DATA		5
#define EI_VERSION	6
#define EI_OSABI	7
#define EI_ABIVERSION	8

#define ELFCLASS32	1
#define ELFCLASS64	2
#define ELFDATA2LSB	1
#define ELFDATA2MSB	2
#define EV_CURRENT	1

/* Header sizes per class. */
#define EHDR32_SIZE	52
#define EHDR64_SIZE	64
#define PHDR32_SIZE	32
#define PHDR64_SIZE	56
#define SHDR32_SIZE	40
#define SHDR64_SIZE	64

/* e_type values that change what counts as anomalous. */
#define ET_NONE		0
#define ET_REL		1
#define ET_EXEC		2
#define ET_DYN		3

#define PT_LOAD		1
#define SHT_NULL	0
#define SHT_NOBITS	8
#define SHT_STRTAB	3

/* Section flags. SHF_ALLOC is the one that decides whether a section becomes part
 * of the process image, which is what separates KOF_SCAN_ELF_NOLOAD from the rest:
 * .comment, .debug_* and .symtab are all kept in the file without it. */
#define SHF_ALLOC	0x2

/* p_flags bits */
#define PF_X		1
#define PF_W		2
#define PF_R		4

/* e_machine values worth normalising. Anything else becomes KOF_ARCH_OTHER. */
#define EM_386		3
#define EM_MIPS		8
#define EM_PPC64	21
#define EM_ARM		40
#define EM_X86_64	62
#define EM_AARCH64	183
#define EM_RISCV	243

/*
 * e_phnum == PN_XNUM means the real count lives in the section table. Not
 * handled yet; flagged so the gap shows up in a corpus rather than silently.
 */
#define PN_XNUM		0xffff

/* SHN_UNDEF as a shstrndx means there is no section name string table. */
#define SHN_UNDEF	0

static uint32_t perm_from_pflags(uint32_t f)
{
	uint32_t p = 0;
	if (f & PF_X) p |= KOF_PERM_X;
	if (f & PF_W) p |= KOF_PERM_W;
	if (f & PF_R) p |= KOF_PERM_R;
	return p;
}

/*
 * Normalise e_machine. Only the common tier uses this; a module that needs the
 * exact value reads e_machine from the ELF view, where the constant it compares
 * against is an ELF constant and therefore comparable.
 */
static uint8_t arch_from_machine(uint16_t m)
{
	switch (m) {
	case EM_386:     return KOF_ARCH_X86;
	case EM_X86_64:  return KOF_ARCH_X86_64;
	case EM_ARM:     return KOF_ARCH_ARM;
	case EM_AARCH64: return KOF_ARCH_ARM64;
	case EM_RISCV:   return KOF_ARCH_RISCV64;
	case EM_MIPS:    return KOF_ARCH_MIPS;
	case EM_PPC64:   return KOF_ARCH_PPC64;
	default:         return KOF_ARCH_OTHER;
	}
}

/* FNV-1a over a NUL terminated name, bounded by the buffer it lives in. Used so
 * a name comparison survives the truncation applied to the stored copy. */
static uint32_t name_hash(kof_buf strtab, uint64_t off, int *out_truncated)
{
	uint32_t h = 2166136261u;
	uint64_t i;

	*out_truncated = 0;
	for (i = 0; ; i++) {
		uint8_t c;
		if (!kof_rd_u8(strtab, off + i, &c) || c == 0)
			break;
		h ^= (uint32_t)c;
		h *= 16777619u;
	}
	if (i >= KOF_ELF_SECNAME_MAX)
		*out_truncated = 1;
	return h;
}

/*
 * Read one program header. The field order differs between classes in a way
 * that is easy to get wrong: p_flags sits after p_type in ELF64 but after
 * p_memsz in ELF32. Keeping both layouts in one place makes the difference
 * reviewable instead of scattered.
 */
static int read_phdr(kof_buf ph, int is64, int be, struct kof_elf_seg *s,
		     uint32_t *out_flags)
{
	if (is64) {
		return kof_rd_u32(ph,  0, be, &s->type)      &&
		       kof_rd_u32(ph,  4, be, out_flags)     &&
		       kof_rd_u64(ph,  8, be, &s->file_off)  &&
		       kof_rd_u64(ph, 16, be, &s->mem_addr)  &&
		       kof_rd_u64(ph, 32, be, &s->file_size) &&
		       kof_rd_u64(ph, 40, be, &s->mem_size);
	}
	{
		uint32_t off32, vaddr32, filesz32, memsz32;
		if (!(kof_rd_u32(ph,  0, be, &s->type)  &&
		      kof_rd_u32(ph,  4, be, &off32)    &&
		      kof_rd_u32(ph,  8, be, &vaddr32)  &&
		      kof_rd_u32(ph, 16, be, &filesz32) &&
		      kof_rd_u32(ph, 20, be, &memsz32)  &&
		      kof_rd_u32(ph, 24, be, out_flags)))
			return 0;
		s->file_off  = off32;
		s->mem_addr  = vaddr32;
		s->file_size = filesz32;
		s->mem_size  = memsz32;
		return 1;
	}
}

/* Read one section header. Returns the name index separately: resolving it
 * needs the string table, which is itself one of the sections. */
static int read_shdr(kof_buf sh, int is64, int be, struct kof_elf_sec *s,
		     uint32_t *out_name_idx)
{
	if (is64) {
		return kof_rd_u32(sh,  0, be, out_name_idx)  &&
		       kof_rd_u32(sh,  4, be, &s->type)      &&
		       kof_rd_u64(sh,  8, be, &s->flags)     &&
		       kof_rd_u64(sh, 16, be, &s->mem_addr)  &&
		       kof_rd_u64(sh, 24, be, &s->file_off)  &&
		       kof_rd_u64(sh, 32, be, &s->file_size);
	}
	{
		uint32_t flags32, addr32, off32, size32;
		if (!(kof_rd_u32(sh,  0, be, out_name_idx) &&
		      kof_rd_u32(sh,  4, be, &s->type)     &&
		      kof_rd_u32(sh,  8, be, &flags32)     &&
		      kof_rd_u32(sh, 12, be, &addr32)      &&
		      kof_rd_u32(sh, 16, be, &off32)       &&
		      kof_rd_u32(sh, 20, be, &size32)))
			return 0;
		s->flags     = flags32;
		s->mem_addr  = addr32;
		s->file_off  = off32;
		s->file_size = size32;
		return 1;
	}
}

/* Overlap in the virtual address space of two PT_LOAD segments. */
static int vaddr_overlap(const struct kof_elf_seg *a, const struct kof_elf_seg *b)
{
	uint64_t a_end, b_end;
	if (a->mem_size == 0 || b->mem_size == 0)
		return 0;
	/* mem_size is untrusted; saturate instead of wrapping. */
	a_end = (a->mem_addr > UINT64_MAX - a->mem_size) ? UINT64_MAX
							 : a->mem_addr + a->mem_size;
	b_end = (b->mem_addr > UINT64_MAX - b->mem_size) ? UINT64_MAX
							 : b->mem_addr + b->mem_size;
	return a->mem_addr < b_end && b->mem_addr < a_end;
}

static void parse_sections(kof_buf file, struct kof_elf_info *info,
			   int is64, int be, uint64_t *anom)
{
	uint64_t shdr_size = is64 ? SHDR64_SIZE : SHDR32_SIZE;
	uint32_t name_idx[KOF_ELF_MAX_SECTIONS];
	kof_buf strtab;
	uint32_t i;

	if (info->shentsize != 0 && info->shentsize != shdr_size)
		*anom |= KOF_ELF_ANOM_SHENTSIZE_ODD;

	info->shnum = info->shnum_claimed;
	if (info->shnum > KOF_ELF_MAX_SECTIONS) {
		info->shnum = KOF_ELF_MAX_SECTIONS;
		*anom |= KOF_ELF_ANOM_SHNUM_CLAMPED;
	}
	if (info->shnum != 0 && info->shoff >= file.n) {
		*anom |= KOF_ELF_ANOM_SHOFF_PAST_EOF;
		info->shnum = 0;
	}
	if (info->shnum == 0) {
		/* Stripped, or the table was unusable. Either way the section
		 * view is absent and only segments can be trusted. */
		*anom |= KOF_ELF_ANOM_SECTAB_MISSING;
		return;
	}

	/*
	 * Stride by the size this class mandates, not by the header's claim: a
	 * wrong shentsize would otherwise walk arbitrary offsets. The claim is
	 * still reported.
	 */
	for (i = 0; i < info->shnum; i++) {
		kof_buf sh = kof_slice(file, info->shoff + i * shdr_size,
				       shdr_size);
		struct kof_elf_sec *s = &info->sec[info->sec_count];

		if (sh.n == 0) {
			*anom |= KOF_ELF_ANOM_SEC_PAST_EOF;
			break;
		}
		memset(s, 0, sizeof *s);
		if (!read_shdr(sh, is64, be, s, &name_idx[info->sec_count])) {
			*anom |= KOF_ELF_ANOM_SEC_PAST_EOF;
			break;
		}

		/* SHT_NOBITS occupies no file bytes, so its file_off says
		 * nothing and must not be range checked as if it did. */
		if (s->type != SHT_NOBITS && s->type != SHT_NULL &&
		    !kof_in_range(file, s->file_off, s->file_size))
			*anom |= KOF_ELF_ANOM_SEC_PAST_EOF;

		info->sec_count++;
	}

	/* Resolve names. The string table is one of the sections just read, so
	 * this cannot be folded into the loop above. */
	if (info->shstrndx == SHN_UNDEF || info->shstrndx >= info->sec_count) {
		if (info->shstrndx != SHN_UNDEF)
			*anom |= KOF_ELF_ANOM_SHSTRNDX_BAD;
		return;
	}

	strtab = kof_slice(file, info->sec[info->shstrndx].file_off,
			   info->sec[info->shstrndx].file_size);
	if (strtab.n == 0) {
		*anom |= KOF_ELF_ANOM_SHSTRNDX_BAD;
		return;
	}

	for (i = 0; i < info->sec_count; i++) {
		struct kof_elf_sec *s = &info->sec[i];
		int truncated = 0;
		uint32_t k;

		if (name_idx[i] >= strtab.n) {
			*anom |= KOF_ELF_ANOM_SECNAME_UNREAD;
			continue;
		}
		s->name_hash = name_hash(strtab, name_idx[i], &truncated);
		if (truncated)
			*anom |= KOF_ELF_ANOM_SECNAME_TRUNC;

		for (k = 0; k + 1 < KOF_ELF_SECNAME_MAX; k++) {
			uint8_t c;
			if (!kof_rd_u8(strtab, name_idx[i] + k, &c) || c == 0)
				break;
			s->name[k] = (char)c;
		}
		s->name[k] = 0;
	}
}

/*
 * Region resolution.
 *
 * Nothing is stored on the context. Every range is computed from info->seg[] and
 * info->sec[], which the parse already filled and which hold every fact needed. A
 * stored region table was tried and removed: it duplicated resident data, so it could
 * disagree with its source, and it needed a cap on extents per region - which for a
 * complement like UNCLAIMED meant merging across claimed bytes.
 *
 * The five ELF regions partition the object: HEADERS, CODE, DATA, NOLOAD and
 * UNCLAIMED cover every byte and overlap in none. So OR-ing bits together scans no
 * byte twice, which is why coalescing is all the deduplication a union needs.
 */

/* A range list under construction, bounded by the caller's buffer. */
struct rlist {
	struct kof_range *v;
	uint32_t n;
	uint32_t cap;
};

/*
 * Append [o, o+n) clipped to the object. Saturating on the end, since both values
 * come from header fields that may be hostile.
 *
 * Order does not matter here; the caller sorts once at the end rather than keeping
 * the list ordered through every insert.
 */
static void rl_add(struct rlist *l, uint64_t obj_size, uint64_t o, uint64_t n)
{
	uint64_t e;

	if (n == 0 || o >= obj_size || l->n >= l->cap)
		return;
	e = (o > UINT64_MAX - n) ? UINT64_MAX : o + n;
	if (e > obj_size)
		e = obj_size;
	if (e <= o)
		return;
	l->v[l->n].off = o;
	l->v[l->n].len = e - o;
	l->n++;
}

/*
 * Sort by offset, then merge anything that touches or overlaps.
 *
 * Insertion sort on purpose: segments and sections are almost always already in
 * offset order, which makes this a linear scan, and the list is bounded by the
 * segment and section counts. A comparison sort with better worst case would be
 * slower on every real input.
 *
 * Merging on touch, not just on overlap, is what lets a pattern spanning the join
 * between two adjacent regions be found - if code ends exactly where data begins,
 * the union is one range.
 */
static uint32_t rl_normalise(struct rlist *l)
{
	uint32_t i, j, w;

	for (i = 1; i < l->n; i++) {
		struct kof_range t = l->v[i];
		for (j = i; j > 0 && l->v[j - 1].off > t.off; j--)
			l->v[j] = l->v[j - 1];
		l->v[j] = t;
	}

	w = 0;
	for (i = 0; i < l->n; i++) {
		if (w > 0) {
			uint64_t we = l->v[w - 1].off + l->v[w - 1].len;
			if (l->v[i].off <= we) {
				uint64_t ie = l->v[i].off + l->v[i].len;
				if (ie > we)
					l->v[w - 1].len = ie - l->v[w - 1].off;
				continue;
			}
		}
		l->v[w++] = l->v[i];
	}
	l->n = w;
	return w;
}

/* End of the front header structures: the ELF header plus the program header
 * table. Where DATA starts, since the first load usually begins at offset 0 and
 * those bytes belong to HEADERS. */
static uint64_t front_end(const struct kof_elf_info *e)
{
	uint64_t h = (e->elf_class == KOF_ELFCLASS_64) ? EHDR64_SIZE : EHDR32_SIZE;

	if (e->phnum && e->phentsize) {
		uint64_t t = e->phoff + (uint64_t)e->phnum * e->phentsize;
		if (t > h)
			h = t;
	}
	return h;
}

/* Everything a header table, segment or section accounts for. The complement of
 * this is UNCLAIMED. */
static void claimed(struct rlist *l, const struct kof_elf_info *e,
		    uint64_t obj_size)
{
	uint32_t i;

	rl_add(l, obj_size, 0, front_end(e));
	if (e->shnum && e->shentsize)
		rl_add(l, obj_size, e->shoff, (uint64_t)e->shnum * e->shentsize);

	/* Every segment, not only PT_LOAD: a PT_NOTE outside any load still
	 * accounts for its bytes. */
	for (i = 0; i < e->seg_count; i++)
		rl_add(l, obj_size, e->seg[i].file_off, e->seg[i].file_size);

	/* SHT_NOBITS occupies no file bytes, and SHT_NULL describes nothing, so
	 * neither claims anything. */
	for (i = 0; i < e->sec_count; i++)
		if (e->sec[i].type != SHT_NULL && e->sec[i].type != SHT_NOBITS)
			rl_add(l, obj_size, e->sec[i].file_off,
			       e->sec[i].file_size);
}

/*
 * Resolve a mask to ranges. Reached through ctx->resolve_scan, so the host never
 * learns that any of this is ELF specific.
 */
static uint32_t elf_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kof_elf_info *e = (const struct kof_elf_info *)ctx->file_header;
	struct rlist l;
	uint64_t hend;
	uint32_t i;

	if (!e || !e->valid || !out || max_out == 0)
		return 0;

	l.v = out;
	l.n = 0;
	l.cap = max_out;
	hend = front_end(e);

	if (mask & KOF_SCAN_ELF_HEADERS) {
		rl_add(&l, ctx->obj_size, 0, hend);
		if (e->shnum && e->shentsize)
			rl_add(&l, ctx->obj_size, e->shoff,
			       (uint64_t)e->shnum * e->shentsize);
	}

	if (mask & KOF_SCAN_ELF_CODE)
		for (i = 0; i < e->seg_count; i++)
			if (e->seg[i].type == PT_LOAD &&
			    (e->seg[i].perm & KOF_PERM_X))
				rl_add(&l, ctx->obj_size, e->seg[i].file_off,
				       e->seg[i].file_size);

	if (mask & KOF_SCAN_ELF_DATA) {
		for (i = 0; i < e->seg_count; i++) {
			uint64_t o, n;
			if (e->seg[i].type != PT_LOAD ||
			    (e->seg[i].perm & KOF_PERM_X))
				continue;
			o = e->seg[i].file_off;
			n = e->seg[i].file_size;
			/* Trim the front load past the header structures: it
			 * starts at offset 0 on a normal binary, and those bytes
			 * are HEADERS. Without this the two regions overlap and
			 * the partition property is lost. */
			if (o < hend) {
				if (o + n <= hend)
					continue;
				n -= hend - o;
				o = hend;
			}
			rl_add(&l, ctx->obj_size, o, n);
		}
	}

	if (mask & KOF_SCAN_ELF_NOLOAD)
		for (i = 0; i < e->sec_count; i++)
			if (e->sec[i].type != SHT_NULL &&
			    e->sec[i].type != SHT_NOBITS &&
			    !(e->sec[i].flags & SHF_ALLOC))
				rl_add(&l, ctx->obj_size, e->sec[i].file_off,
				       e->sec[i].file_size);

	if (mask & KOF_SCAN_ELF_UNCLAIMED) {
		/*
		 * The complement, built in a scratch list and inverted into the
		 * caller's buffer. Scratch is needed because the claimed set has
		 * to be complete and normalised before it can be inverted, and it
		 * is larger than the result.
		 */
		struct kof_range cv[KOF_ELF_MAX_SEGMENTS + KOF_ELF_MAX_SECTIONS + 2];
		struct rlist c;
		uint64_t cursor = 0;

		c.v = cv;
		c.n = 0;
		c.cap = (uint32_t)(sizeof cv / sizeof cv[0]);
		claimed(&c, e, ctx->obj_size);
		rl_normalise(&c);

		for (i = 0; i < c.n; i++) {
			if (c.v[i].off > cursor)
				rl_add(&l, ctx->obj_size, cursor,
				       c.v[i].off - cursor);
			cursor = c.v[i].off + c.v[i].len;
		}
		if (cursor < ctx->obj_size)
			rl_add(&l, ctx->obj_size, cursor, ctx->obj_size - cursor);
	}

	return rl_normalise(&l);
}

int kof_elf_parse(kof_buf file, struct kof_elf_info *info,
		  struct kof_obj_ctx *ctx)
{
	uint64_t anom = 0;
	int is64, be;
	uint64_t ehdr_size, phdr_size;
	uint8_t cls, data, ver, osabi, abiver;
	uint32_t i, j;

	/*
	 * Only the header and the counts are cleared. The segment and section
	 * arrays are left alone: nothing past seg_count or sec_count is ever
	 * read, and zeroing 11KB for every file in a scan would be pure waste.
	 */
	memset(info, 0, offsetof(struct kof_elf_info, seg));
	info->version = KOF_ELF_INFO_VERSION;
	info->min_vaddr = KOF_NA;

	ctx->obj_size = file.n;
	ctx->entry_off = KOF_NA;
	ctx->arch = KOF_ARCH_ANY;
	ctx->file_header = 0;
	/* Cleared on the way in: a failed identification must not leave a resolver
	 * from a previous file on a reused context. KOF_SCAN_ALL still works
	 * without one, since the host answers that itself. */
	ctx->resolve_scan = 0;

	/* Magic is the only thing that decides "is this ELF". */
	if (!kof_in_range(file, EI_MAG0, 4) ||
	    memcmp(file.p + EI_MAG0, "\177ELF", 4) != 0) {
		info->anomalies = KOF_ELF_ANOM_BAD_MAGIC;
		return 0;
	}
	info->valid    = 1;
	ctx->format = KOF_FMT_ELF;
	ctx->file_header = info;

	if (!kof_rd_u8(file, EI_CLASS, &cls))         cls = 0;
	if (!kof_rd_u8(file, EI_DATA, &data))         data = 0;
	if (!kof_rd_u8(file, EI_VERSION, &ver))       ver = 0;
	if (!kof_rd_u8(file, EI_OSABI, &osabi))       osabi = 0;
	if (!kof_rd_u8(file, EI_ABIVERSION, &abiver)) abiver = 0;

	info->os_abi      = osabi;
	info->abi_version = abiver;

	switch (cls) {
	case ELFCLASS32: info->elf_class = KOF_ELFCLASS_32; is64 = 0; break;
	case ELFCLASS64: info->elf_class = KOF_ELFCLASS_64; is64 = 1; break;
	default:
		info->elf_class = KOF_ELFCLASS_NONE;
		anom |= KOF_ELF_ANOM_BAD_CLASS;
		/* Assume 32 bit to keep collecting. Widths may be wrong but the
		 * anomaly says so, and partial facts beat none. */
		is64 = 0;
		break;
	}

	switch (data) {
	case ELFDATA2LSB: info->elf_data = KOF_ELFDATA_LE; be = 0; break;
	case ELFDATA2MSB: info->elf_data = KOF_ELFDATA_BE; be = 1; break;
	default:
		info->elf_data = KOF_ELFDATA_NONE;
		anom |= KOF_ELF_ANOM_BAD_ENDIAN;
		be = 0;
		break;
	}

	if (ver != EV_CURRENT)
		anom |= KOF_ELF_ANOM_BAD_VERSION;

	ehdr_size = is64 ? EHDR64_SIZE : EHDR32_SIZE;
	phdr_size = is64 ? PHDR64_SIZE : PHDR32_SIZE;

	if (file.n < ehdr_size)
		anom |= KOF_ELF_ANOM_TRUNCATED_HEADER;

	/* Offsets 16..24 are class independent. */
	kof_rd_u16(file, 16, be, &info->e_type);
	kof_rd_u16(file, 18, be, &info->e_machine);
	kof_rd_u32(file, 20, be, &info->e_version);

	if (is64) {
		kof_rd_u64(file, 24, be, &info->entry_addr);
		kof_rd_u64(file, 32, be, &info->phoff);
		kof_rd_u64(file, 40, be, &info->shoff);
		kof_rd_u16(file, 54, be, &info->phentsize);
		kof_rd_u16(file, 56, be, &info->phnum_claimed);
		kof_rd_u16(file, 58, be, &info->shentsize);
		kof_rd_u16(file, 60, be, &info->shnum_claimed);
		kof_rd_u16(file, 62, be, &info->shstrndx);
	} else {
		uint32_t v;
		if (kof_rd_u32(file, 24, be, &v)) info->entry_addr = v;
		if (kof_rd_u32(file, 28, be, &v)) info->phoff = v;
		if (kof_rd_u32(file, 32, be, &v)) info->shoff = v;
		kof_rd_u16(file, 42, be, &info->phentsize);
		kof_rd_u16(file, 44, be, &info->phnum_claimed);
		kof_rd_u16(file, 46, be, &info->shentsize);
		kof_rd_u16(file, 48, be, &info->shnum_claimed);
		kof_rd_u16(file, 50, be, &info->shstrndx);
	}

	ctx->arch = arch_from_machine(info->e_machine);

	/*
	 * A zero entry point is only anomalous for ET_EXEC. Measured over
	 * /usr/bin and /usr/lib, 535 of 1316 objects are shared libraries with a
	 * legitimately zero e_entry and 12 more are relocatable objects; an
	 * unconditional bit fires on 42% of clean files and discriminates
	 * nothing. ET_DYN covers both PIE executables and shared libraries, so
	 * e_type cannot separate those and neither is anomalous.
	 */
	if (info->entry_addr == 0 && info->e_type == ET_EXEC)
		anom |= KOF_ELF_ANOM_ENTRY_ZERO;

	/* ---- program headers -------------------------------------------- */

	if (info->phnum_claimed == PN_XNUM)
		anom |= KOF_ELF_ANOM_PHNUM_CLAMPED; /* real count is in shdr[0] */

	if (info->phentsize != 0 && info->phentsize != phdr_size)
		anom |= KOF_ELF_ANOM_PHENTSIZE_ODD;

	info->phnum = info->phnum_claimed;
	if (info->phnum > KOF_ELF_MAX_SEGMENTS) {
		info->phnum = KOF_ELF_MAX_SEGMENTS;
		anom |= KOF_ELF_ANOM_PHNUM_CLAMPED;
	}
	if (info->phnum != 0 && info->phoff >= file.n) {
		anom |= KOF_ELF_ANOM_PHOFF_PAST_EOF;
		info->phnum = 0;
	}

	for (i = 0; i < info->phnum; i++) {
		kof_buf ph = kof_slice(file, info->phoff + i * phdr_size,
				       phdr_size);
		struct kof_elf_seg *s = &info->seg[info->seg_count];
		uint32_t flags = 0;

		if (ph.n == 0) {
			anom |= KOF_ELF_ANOM_SEG_PAST_EOF;
			break;
		}
		memset(s, 0, sizeof *s);
		if (!read_phdr(ph, is64, be, s, &flags)) {
			anom |= KOF_ELF_ANOM_SEG_PAST_EOF;
			break;
		}
		s->perm = perm_from_pflags(flags);
		info->seg_count++;

		if (s->type != PT_LOAD)
			continue;

		if (s->file_size > s->mem_size)
			anom |= KOF_ELF_ANOM_SEG_FILESZ_GT_MEM;
		if (!kof_in_range(file, s->file_off, s->file_size))
			anom |= KOF_ELF_ANOM_SEG_PAST_EOF;

		if (info->min_vaddr == KOF_NA || s->mem_addr < info->min_vaddr)
			info->min_vaddr = s->mem_addr;
		{
			uint64_t end = (s->mem_addr > UINT64_MAX - s->mem_size)
					? UINT64_MAX : s->mem_addr + s->mem_size;
			if (end > info->max_vaddr)
				info->max_vaddr = end;
		}
		info->load_count++;
	}

	/*
	 * Relocatable objects have no PT_LOAD by design, and a truncated header
	 * already reports itself; flagging either here only adds noise. Only an
	 * executable or shared object with nothing to load is odd.
	 */
	if (info->load_count == 0 &&
	    (info->e_type == ET_EXEC || info->e_type == ET_DYN))
		anom |= KOF_ELF_ANOM_NO_LOAD_SEGMENT;

	/* Pairwise overlap over PT_LOAD only. seg_count is clamped, so bounded. */
	for (i = 0; i < info->seg_count && !(anom & KOF_ELF_ANOM_SEG_OVERLAP); i++) {
		if (info->seg[i].type != PT_LOAD)
			continue;
		for (j = i + 1; j < info->seg_count; j++) {
			if (info->seg[j].type != PT_LOAD)
				continue;
			if (vaddr_overlap(&info->seg[i], &info->seg[j])) {
				anom |= KOF_ELF_ANOM_SEG_OVERLAP;
				break;
			}
		}
	}

	/* ---- entry point ------------------------------------------------- */

	/*
	 * Three outcomes are kept distinct because they mean different things:
	 * not mapped at all, mapped but only as zero fill so the bytes are
	 * absent from the file, and mapped into a region that is not executable.
	 * Collapsing them would discard the strongest signals available here.
	 */
	if (info->entry_addr != 0 && info->load_count != 0) {
		int found = 0;
		for (i = 0; i < info->seg_count; i++) {
			const struct kof_elf_seg *s = &info->seg[i];
			uint64_t delta;

			if (s->type != PT_LOAD || info->entry_addr < s->mem_addr)
				continue;
			delta = info->entry_addr - s->mem_addr;
			if (delta >= s->mem_size)
				continue;

			found = 1;
			info->entry_perm = s->perm;
			if (!(s->perm & KOF_PERM_X))
				anom |= KOF_ELF_ANOM_ENTRY_NOT_EXEC;

			if (delta >= s->file_size) {
				anom |= KOF_ELF_ANOM_ENTRY_ZEROFILL;
				ctx->entry_off = KOF_BROKEN;
			} else {
				uint64_t off = s->file_off + delta;
				if (kof_in_range(file, off, 1))
					ctx->entry_off = off;
				else {
					anom |= KOF_ELF_ANOM_SEG_PAST_EOF;
					ctx->entry_off = KOF_BROKEN;
				}
			}
			break;
		}
		if (!found) {
			anom |= KOF_ELF_ANOM_ENTRY_UNMAPPED;
			ctx->entry_off = KOF_BROKEN;
		}
	} else if (info->entry_addr != 0) {
		/* Declares an entry but has nothing loaded to resolve it in. */
		ctx->entry_off = KOF_BROKEN;
	}

	/* ---- section headers -------------------------------------------- */

	parse_sections(file, info, is64, be, &anom);

	/* Regions are computed on demand from the tables just filled, not stored.
	 * Attaching the resolver is the whole of it. */
	ctx->resolve_scan = elf_resolve_scan;

	info->anomalies = anom;
	return 1;
}
