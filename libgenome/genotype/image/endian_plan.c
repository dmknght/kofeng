/*
 * endian_plan.c - what of a big-endian ELF is swapped, and the swap itself.
 *
 * The decisions are in endian.h and are not repeated: this file builds the list
 * of spans from the parse and from the object's own tables, and applies it. The
 * plan is built over the bytes as they are - before anything is swapped - because
 * the tables it reads (section headers, symbols, notes, the GNU hash header) are
 * still in the order they were written in.
 */

#define _GNU_SOURCE

#include <genotype/image/endian.h>
#include <genotype/image/elf_image.h>

#include <stdlib.h>
#include <string.h>

/* ---- the layouts -------------------------------------------------------------- */

/*
 * A field is 2, 4 or 8 (swapped) or SK(n), n bytes passed over: a name, a byte
 * pair, the 16 bytes of e_ident. `lay_size` is the sum, so an entry's size is
 * written once, as the fields.
 */
#define SK(n) ((uint8_t)(0x80u | (n)))

struct layout {
	uint8_t f[KGENOME_ENDIAN_FIELDS];       /* 0 ends the list */
};

static const struct layout LAY[KGENOME_ENDIAN_L_COUNT] = {
	[KGENOME_ENDIAN_L_W2]     = { { 2 } },
	[KGENOME_ENDIAN_L_W4]     = { { 4 } },
	[KGENOME_ENDIAN_L_W8]     = { { 8 } },
	/* e_ident, e_type, e_machine, e_version, entry, phoff, shoff, flags,
	 * ehsize, phentsize, phnum, shentsize, shnum, shstrndx */
	[KGENOME_ENDIAN_L_EHDR32] = { { SK(16), 2, 2, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2 } },
	[KGENOME_ENDIAN_L_EHDR64] = { { SK(16), 2, 2, 4, 8, 8, 8, 4, 2, 2, 2, 2, 2, 2 } },
	/* type, offset, vaddr, paddr, filesz, memsz, flags, align */
	[KGENOME_ENDIAN_L_PHDR32] = { { 4, 4, 4, 4, 4, 4, 4, 4 } },
	/* type, flags, offset, vaddr, paddr, filesz, memsz, align */
	[KGENOME_ENDIAN_L_PHDR64] = { { 4, 4, 8, 8, 8, 8, 8, 8 } },
	[KGENOME_ENDIAN_L_SHDR32] = { { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 } },
	/* name, type, flags, addr, offset, size, link, info, addralign, entsize */
	[KGENOME_ENDIAN_L_SHDR64] = { { 4, 4, 8, 8, 8, 8, 4, 4, 8, 8 } },
	/* name, value, size, info + other, shndx */
	[KGENOME_ENDIAN_L_SYM32]  = { { 4, 4, 4, SK(2), 2 } },
	/* name, info + other, shndx, value, size */
	[KGENOME_ENDIAN_L_SYM64]  = { { 4, SK(2), 2, 8, 8 } },
	[KGENOME_ENDIAN_L_REL32]  = { { 4, 4 } },
	[KGENOME_ENDIAN_L_RELA32] = { { 4, 4, 4 } },
	[KGENOME_ENDIAN_L_REL64]  = { { 8, 8 } },
	[KGENOME_ENDIAN_L_RELA64] = { { 8, 8, 8 } },
	/* r_offset, r_sym (a word), then r_ssym r_type3 r_type2 r_type: four bytes */
	[KGENOME_ENDIAN_L_MREL64] = { { 8, 4, SK(4) } },
	[KGENOME_ENDIAN_L_MRELA64] = { { 8, 4, SK(4), 8 } },
	[KGENOME_ENDIAN_L_DYN32]  = { { 4, 4 } },
	[KGENOME_ENDIAN_L_DYN64]  = { { 8, 8 } },
	[KGENOME_ENDIAN_L_NOTE]   = { { 4, 4, 4 } },
};

static uint32_t lay_size(unsigned lay)
{
	uint32_t s = 0, i;

	for (i = 0; i < KGENOME_ENDIAN_FIELDS && LAY[lay].f[i]; i++)
		s += (LAY[lay].f[i] & 0x80u) ? (LAY[lay].f[i] & 0x7fu) : LAY[lay].f[i];
	return s;
}

/* One unit of 2, 4 or 8 bytes, reversed in place; 1 when its bytes changed. memcpy and
 * the byte-swap builtins, which the compilers turn into a load, a bswap and a store:
 * this runs once per instruction word of a big-endian object. */
static unsigned unit_swap(uint8_t *q, uint32_t w)
{
	if (w == 4u) {
		uint32_t x, y;

		memcpy(&x, q, 4);
		y = __builtin_bswap32(x);
		memcpy(q, &y, 4);
		return x != y;
	}
	if (w == 2u) {
		uint16_t x, y;

		memcpy(&x, q, 2);
		y = __builtin_bswap16(x);
		memcpy(q, &y, 2);
		return x != y;
	}
	{
		uint64_t x, y;

		memcpy(&x, q, 8);
		y = __builtin_bswap64(x);
		memcpy(q, &y, 8);
		return x != y;
	}
}

/* One entry, in place. Returns how many of its fields changed. */
static uint64_t entry_swap(uint8_t *p, unsigned lay)
{
	uint64_t changed = 0;
	uint32_t i;

	for (i = 0; i < KGENOME_ENDIAN_FIELDS && LAY[lay].f[i]; i++) {
		uint32_t w = LAY[lay].f[i];

		if (w & 0x80u) {
			p += w & 0x7fu;
			continue;
		}
		changed += unit_swap(p, w);
		p += w;
	}
	return changed;
}

/* ---- the architectures --------------------------------------------------------- */

/* e_flags bits of MIPS that make the instruction unit two bytes. */
#define EF_MIPS_ASE_MICRO 0x02000000u
#define EF_MIPS_ASE_M16   0x04000000u

int kgenome_endian_has_twin(unsigned arch)
{
	switch (arch) {
	case KGENOME_ARCH_MIPS:
	case KGENOME_ARCH_MIPS64:
	case KGENOME_ARCH_ARM:
	case KGENOME_ARCH_ARM64:
	case KGENOME_ARCH_PPC64:
	case KGENOME_ARCH_SH:
	case KGENOME_ARCH_MICROBLAZE:
		return 1;
	default:
		return 0;
	}
}

uint32_t kgenome_endian_code_unit(const struct kgenome_obj *obj)
{
	const struct kgenome_elf_info *e;

	if (!obj || obj->format != KGENOME_FMT_ELF || !obj->file_header)
		return 0;
	e = kgenome_obj_elf(obj);
	switch (obj->arch) {
	case KGENOME_ARCH_MIPS:
	case KGENOME_ARCH_MIPS64:
		return (e->e_flags & (EF_MIPS_ASE_MICRO | EF_MIPS_ASE_M16)) ? 2u : 4u;
	case KGENOME_ARCH_ARM:
		return kgenome_obj_code_little_endian(obj) ? 0u : 4u;
	case KGENOME_ARCH_PPC64:
	case KGENOME_ARCH_MICROBLAZE:
		return 4u;
	case KGENOME_ARCH_SH:
		return 2u;
	default:
		return 0;               /* AArch64: little-endian code in both orders */
	}
}

int kgenome_endian_wanted(const struct kgenome_obj *obj)
{
	return kgenome_obj_big_endian(obj) && kgenome_endian_has_twin(obj->arch) &&
	       kgenome_obj_elf(obj)->valid;
}

/* ---- the plan ------------------------------------------------------------------ */

void kgenome_endian_plan_free(struct kgenome_endian_plan *p)
{
	if (!p)
		return;
	free(p->v);
	memset(p, 0, sizeof *p);
}

/*
 * Add a span, clipped to the object and to whole entries, in sorted order, unless
 * it overlaps one already there. Returns 1 for added or harmlessly empty, 0 when
 * the span was refused - and the status says why, because a refused span is bytes
 * left in the old order.
 */
static int span_add(struct kgenome_endian_plan *p, uint64_t n, uint64_t off,
		    uint64_t len, unsigned lay)
{
	uint32_t es = lay_size(lay), lo, hi;
	struct kgenome_endian_span *g;

	if (off >= n)
		return 1;
	if (len > n - off)
		len = n - off;
	len -= len % es;
	if (!len)
		return 1;
	/* First span whose end is past `off`. */
	lo = 0;
	hi = p->n;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (p->v[mid].off + p->v[mid].len <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (lo < p->n && p->v[lo].off < off + len) {
		p->dropped++;           /* the object's own structure overlaps: not a limit */
		return 0;
	}
	if (p->n >= KGENOME_ENDIAN_MAX_SPANS) {
		p->status = kgenome_status_merge(p->status, KGENOME_TRUNCATED);
		return 0;
	}
	if (p->n == p->cap) {
		uint32_t nc = p->cap ? p->cap * 2u : 64u;

		g = realloc(p->v, (size_t)nc * sizeof *g);
		if (!g) {
			p->status = kgenome_status_merge(p->status, KGENOME_NOMEM);
			return 0;
		}
		p->v = g;
		p->cap = nc;
	}
	memmove(p->v + lo + 1u, p->v + lo, (size_t)(p->n - lo) * sizeof *p->v);
	p->v[lo].off = off;
	p->v[lo].len = len;
	p->v[lo].lay = (uint8_t)lay;
	p->n++;
	return 1;
}

/* ---- code ---------------------------------------------------------------------- */

/*
 * One extent of code in `unit`-byte units, from the first unit that starts on
 * the unit's own alignment IN THE ADDRESS SPACE the code runs in: a section whose
 * address is not a multiple of the unit has a partial unit at its start that no
 * instruction owns, and swapping from the section's first byte would cut every
 * word in half.
 *
 * It goes AROUND what the plan already holds: the header tables of a stripped
 * object sit inside the one executable segment that is all it has, and they are
 * not instructions.
 */
static void code_span(struct kgenome_endian_plan *p, uint64_t n, uint64_t at,
		      uint64_t have, uint64_t addr, unsigned unit)
{
	uint64_t end = at + have, lead;
	uint32_t lo, hi;

	if (!unit)
		return;
	while (at < end) {
		/* First span that ends past `at`. */
		lo = 0;
		hi = p->n;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo) / 2u;

			if (p->v[mid].off + p->v[mid].len <= at)
				lo = mid + 1u;
			else
				hi = mid;
		}
		if (lo < p->n && p->v[lo].off <= at) {  /* inside a span: step past it */
			at = p->v[lo].off + p->v[lo].len;
			continue;
		}
		{
			uint64_t stop = lo < p->n && p->v[lo].off < end ? p->v[lo].off : end;

			lead = (unit - ((addr + (at - (end - have))) % unit)) % unit;
			if (stop > at && stop - at > lead)
				(void)span_add(p, n, at + lead, stop - at - lead,
					       unit == 4u ? KGENOME_ENDIAN_L_W4 : KGENOME_ENDIAN_L_W2);
			at = stop;
		}
	}
}

/*
 * A stripped object has no section table, so the executable SEGMENT is the only
 * extent of code it has - and a linker puts .rodata in it beside .text. A string
 * literal swapped by words is a string nobody can read, so the runs of printable
 * ASCII long enough to be one (STR_RUN bytes, more than any run of instruction
 * bytes has been seen to hold) are left as they are, widened to whole units. What
 * is cut around is reported nowhere else: it is a property of the bytes.
 */
#define STR_RUN 8u

static int text_byte(uint8_t c)
{
	return (uint8_t)(c - 0x20u) < 0x5fu || c == '\n' || c == '\r' || c == '\t';
}

static void code_segment(struct kgenome_endian_plan *p, kof_buf f, uint64_t at, uint64_t have,
			 uint64_t addr, unsigned unit)
{
	uint64_t i = 0, from = 0, a0 = addr - at;       /* address of file offset x is a0 + x */

	while (i < have) {
		uint64_t j = i, ra, rb;

		if (!text_byte(f.p[at + i])) {
			i++;
			continue;
		}
		while (j < have && text_byte(f.p[at + j]))
			j++;
		if (j - i >= STR_RUN) {
			/* Whole units: from the unit holding the first byte to the end of the
			 * unit holding the last (and the NULs after it in that unit). */
			ra = i - ((a0 + at + i) % unit);
			rb = j + ((unit - ((a0 + at + j) % unit)) % unit);
			if (ra > i)
				ra = 0;         /* wrapped: the run starts in the first unit */
			if (rb > have)
				rb = have;
			if (ra > from)
				code_span(p, f.n, at + from, ra - from, addr + from, unit);
			if (rb > from)
				from = rb;
		}
		i = j;
	}
	if (have > from)
		code_span(p, f.n, at + from, have - from, addr + from, unit);
}

/* ARM mapping symbols: $a (ARM), $t (Thumb), $d (data), by file offset. */
struct mark {
	uint64_t off;
	uint8_t  kind;          /* 'a', 't', 'd' */
};

static int mark_cmp(const void *a, const void *b)
{
	const struct mark *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

/*
 * The mapping symbols of the object that fall in executable sections. An object
 * without them (stripped) returns none and the caller falls back to its default.
 * Bounded by the symbol table itself and by KGENOME_ENDIAN_MAX_SPANS: a mark past
 * that bound would be a span past it.
 */
static struct mark *arm_marks(kof_buf f, const struct kgenome_elf_info *e,
			      uint32_t *out_n, enum kgenome_status *st)
{
	struct kgenome_elf_symtab t;
	struct mark *m = NULL;
	uint32_t n = 0, cap = 0;
	uint64_t i;

	*out_n = 0;
	if (!kgenome_elf_symtab_of(f, e, KGENOME_ELF_SYMTAB_FULL, &t) || !t.strn)
		return NULL;
	for (i = 1; i < t.n; i++) {
		struct kgenome_elf_symbol sy;
		const struct kgenome_elf_sec *sec;
		uint8_t c0, c1, c2;

		if (!kgenome_elf_symbol_at(f, &t, i, &sy))
			break;
		if (!sy.nameoff || sy.nameoff + 3u > t.strn || sy.shndx == 0 ||
		    sy.shndx >= e->sec_count || sy.shndx >= KGENOME_ELF_MAX_SECTIONS)
			continue;
		if (!kof_rd_u8(f, t.str + sy.nameoff, &c0) || c0 != '$' ||
		    !kof_rd_u8(f, t.str + sy.nameoff + 1u, &c1) ||
		    (c1 != 'a' && c1 != 't' && c1 != 'd') ||
		    !kof_rd_u8(f, t.str + sy.nameoff + 2u, &c2) || (c2 != 0 && c2 != '.'))
			continue;
		sec = &e->sec[sy.shndx];
		if (!kgenome_elf_sec_is_code(sec) || sy.value < sec->mem_addr ||
		    sy.value - sec->mem_addr >= sec->file_size)
			continue;
		if (n == cap) {
			uint32_t nc = cap ? cap * 2u : 256u;
			struct mark *g;

			if (nc > KGENOME_ENDIAN_MAX_SPANS) {
				*st = kgenome_status_merge(*st, KGENOME_TRUNCATED);
				break;
			}
			g = realloc(m, (size_t)nc * sizeof *g);
			if (!g) {
				*st = kgenome_status_merge(*st, KGENOME_NOMEM);
				break;
			}
			m = g;
			cap = nc;
		}
		m[n].off = sec->file_off + (sy.value - sec->mem_addr);
		m[n].kind = c1;
		n++;
	}
	if (n > 1u)
		qsort(m, n, sizeof *m, mark_cmp);
	*out_n = n;
	return m;
}

/* The unit a mapping symbol switches to: ARM 4, Thumb 2, data 0 (left alone). */
static unsigned kind_unit(uint8_t kind)
{
	return kind == 'a' ? 4u : kind == 't' ? 2u : 0u;
}

/* An ARM extent cut at its mapping symbols: each stretch in its own unit. */
static void arm_code(struct kgenome_endian_plan *p, uint64_t n, uint64_t at,
		     uint64_t have, uint64_t addr, unsigned dflt,
		     const struct mark *m, uint32_t nm)
{
	uint64_t pos = at, end = at + have;
	unsigned cur = dflt;
	uint32_t k = 0;

	/* What is in force where the extent starts: the last mark at or before. */
	while (k < nm && m[k].off <= at)
		cur = kind_unit(m[k++].kind);
	while (pos < end) {
		uint64_t stop = k < nm && m[k].off < end ? m[k].off : end;

		if (stop > pos)
			code_span(p, n, pos, stop - pos, addr + (pos - at), cur);
		pos = stop;
		while (k < nm && m[k].off <= pos)
			cur = kind_unit(m[k++].kind);
	}
}

static void plan_code(struct kgenome_endian_plan *p, kof_buf f,
		      const struct kgenome_obj *obj, const struct kgenome_elf_info *e,
		      int segments)
{
	unsigned unit = (unsigned)p->code_unit;
	struct mark *marks = NULL;
	uint32_t nm = 0, i;
	unsigned dflt = unit;

	/* The sections' code is claimed before the headers and the segments' after: a
	 * section is instructions, a segment is only where the loader allows them. */
	if (!unit || (segments != (e->sec_count == 0)))
		return;
	if (obj->arch == KGENOME_ARCH_ARM) {
		/* No mapping symbols: Thumb when the entry point says so, else ARM. */
		dflt = (e->entry_addr & 1u) ? 2u : 4u;
		marks = arm_marks(f, e, &nm, &p->status);
	}
	if (e->sec_count) {
		for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			const struct kgenome_elf_sec *c = &e->sec[i];
			uint64_t at, have;

			if (!kgenome_elf_sec_is_code(c))
				continue;
			have = kgenome_elf_sec_extent(c, f.n, &at);
			if (!have)
				continue;
			if (obj->arch == KGENOME_ARCH_ARM)
				arm_code(p, f.n, at, have, c->mem_addr + (at - c->file_off), dflt,
					 marks, nm);
			else
				code_span(p, f.n, at, have, c->mem_addr + (at - c->file_off), unit);
		}
	} else {
		/* No section table: the executable segments, which hold what the
		 * loader maps executable - the instructions and what the linker put
		 * beside them. */
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++) {
			const struct kgenome_elf_seg *g = &e->seg[i];
			uint64_t at, have;

			if (!kgenome_elf_seg_is_code(g))
				continue;
			have = kgenome_elf_seg_extent(g, f.n, &at);
			if (!have)
				continue;
			code_segment(p, f, at, have, g->mem_addr + (at - g->file_off),
				     obj->arch == KGENOME_ARCH_ARM ? dflt : unit);
		}
	}
	free(marks);
}

/* ---- headers and tables ---------------------------------------------------------- */

#define SHT_SYMTAB       2u
#define SHT_RELA         4u
#define SHT_HASH         5u
#define SHT_DYNAMIC      6u
#define SHT_NOTE         7u
#define SHT_REL          9u
#define SHT_DYNSYM       11u
#define SHT_INIT_ARRAY   14u
#define SHT_FINI_ARRAY   15u
#define SHT_PREINIT      16u
#define SHT_GNU_HASH     0x6ffffff6u
#define SHT_GNU_VERSYM   0x6fffffffu
#define SHT_ARM_EXIDX    0x70000001u
#define SHT_MIPS_REGINFO 0x70000006u

/* The notes of a section: the three words of each header, and no more. */
static void plan_notes(struct kgenome_endian_plan *p, kof_buf f, uint64_t off, uint64_t len)
{
	uint64_t at = 0;

	while (at + 12u <= len) {
		uint32_t nsz, dsz;
		uint64_t step;

		/* The header is still in the file's order: big-endian. */
		if (!kof_rd_u32(f, off + at, 1, &nsz) || !kof_rd_u32(f, off + at + 4u, 1, &dsz))
			break;
		if (!span_add(p, f.n, off + at, 12u, KGENOME_ENDIAN_L_NOTE))
			break;
		step = 12u + (((uint64_t)nsz + 3u) & ~(uint64_t)3u) +
		       (((uint64_t)dsz + 3u) & ~(uint64_t)3u);
		if (step > len - at)
			break;
		at += step;
	}
}

/* DT_GNU_HASH: four words, the bloom filter in the class's word, words after. */
static void plan_gnu_hash(struct kgenome_endian_plan *p, kof_buf f, uint64_t off,
			  uint64_t len, int is64)
{
	uint32_t bloom;
	uint64_t cw = is64 ? 8u : 4u, bl;

	if (len < 16u) {
		(void)span_add(p, f.n, off, len, KGENOME_ENDIAN_L_W4);
		return;
	}
	if (!kof_rd_u32(f, off + 8u, 1, &bloom))
		return;
	(void)span_add(p, f.n, off, 16u, KGENOME_ENDIAN_L_W4);
	bl = (uint64_t)bloom * cw;
	if (bl > len - 16u)
		bl = len - 16u;
	(void)span_add(p, f.n, off + 16u, bl, is64 ? KGENOME_ENDIAN_L_W8 : KGENOME_ENDIAN_L_W4);
	(void)span_add(p, f.n, off + 16u + bl, len - 16u - bl, KGENOME_ENDIAN_L_W4);
}

static void plan_section(struct kgenome_endian_plan *p, kof_buf f, const struct kgenome_obj *obj,
			 const struct kgenome_elf_info *e, const struct kgenome_elf_sec *c)
{
	int is64 = e->elf_class == KGENOME_ELFCLASS_64;
	int mips64 = is64 && obj->arch == KGENOME_ARCH_MIPS64;
	uint64_t at, have;

	if (kgenome_elf_sec_is_code(c))
		return;                 /* its words are code, planned above */
	have = kgenome_elf_sec_extent(c, f.n, &at);
	if (!have)
		return;
	switch (c->type) {
	case SHT_SYMTAB:
	case SHT_DYNSYM:
		(void)span_add(p, f.n, at, have,
			       is64 ? KGENOME_ENDIAN_L_SYM64 : KGENOME_ENDIAN_L_SYM32);
		break;
	case SHT_REL:
		(void)span_add(p, f.n, at, have, mips64 ? KGENOME_ENDIAN_L_MREL64
				: is64 ? KGENOME_ENDIAN_L_REL64 : KGENOME_ENDIAN_L_REL32);
		break;
	case SHT_RELA:
		(void)span_add(p, f.n, at, have, mips64 ? KGENOME_ENDIAN_L_MRELA64
				: is64 ? KGENOME_ENDIAN_L_RELA64 : KGENOME_ENDIAN_L_RELA32);
		break;
	case SHT_DYNAMIC:
		(void)span_add(p, f.n, at, have,
			       is64 ? KGENOME_ENDIAN_L_DYN64 : KGENOME_ENDIAN_L_DYN32);
		break;
	case SHT_HASH:
	case SHT_ARM_EXIDX:
	case SHT_MIPS_REGINFO:
		(void)span_add(p, f.n, at, have, KGENOME_ENDIAN_L_W4);
		break;
	case SHT_GNU_HASH:
		plan_gnu_hash(p, f, at, have, is64);
		break;
	case SHT_GNU_VERSYM:
		(void)span_add(p, f.n, at, have, KGENOME_ENDIAN_L_W2);
		break;
	case SHT_INIT_ARRAY:
	case SHT_FINI_ARRAY:
	case SHT_PREINIT:
		(void)span_add(p, f.n, at, have, is64 ? KGENOME_ENDIAN_L_W8 : KGENOME_ENDIAN_L_W4);
		break;
	case SHT_NOTE:
		plan_notes(p, f, at, have);
		break;
	default:
		break;
	}
}

/* The two header tables, each only when its entry size is the class's. */
static void plan_tables(struct kgenome_endian_plan *p, kof_buf f,
			const struct kgenome_elf_info *e)
{
	int is64 = e->elf_class == KGENOME_ELFCLASS_64;

	if (e->phentsize == (is64 ? 56u : 32u) && e->phnum)
		(void)span_add(p, f.n, e->phoff, (uint64_t)e->phnum * e->phentsize,
			       is64 ? KGENOME_ENDIAN_L_PHDR64 : KGENOME_ENDIAN_L_PHDR32);
	if (e->shentsize == (is64 ? 64u : 40u) && e->shnum_claimed)
		(void)span_add(p, f.n, e->shoff, (uint64_t)e->shnum_claimed * e->shentsize,
			       is64 ? KGENOME_ENDIAN_L_SHDR64 : KGENOME_ENDIAN_L_SHDR32);
}

enum kgenome_status kgenome_endian_plan_build(kof_buf f, const struct kgenome_obj *obj,
					      struct kgenome_endian_plan *out)
{
	const struct kgenome_elf_info *e;
	int is64;
	uint32_t i;

	memset(out, 0, sizeof *out);
	if (!obj || !f.p || !kgenome_endian_wanted(obj))
		return KGENOME_OK;
	e = kgenome_obj_elf(obj);
	is64 = e->elf_class == KGENOME_ELFCLASS_64;
	if (f.n < (is64 ? 64u : 52u)) {
		out->status = KGENOME_BAD_INPUT;        /* a cut header: nothing is known */
		return out->status;
	}
	out->code_unit = (uint8_t)kgenome_endian_code_unit(obj);
	/* In the priority order of endian.h: code, the header, the tables. */
	plan_code(out, f, obj, e, 0);
	if (span_add(out, f.n, 0, is64 ? 64u : 52u,
		     is64 ? KGENOME_ENDIAN_L_EHDR64 : KGENOME_ENDIAN_L_EHDR32) &&
	    f.p[5] == 2u)
		out->ident = 1;
	plan_tables(out, f, e);
	plan_code(out, f, obj, e, 1);
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++)
		plan_section(out, f, obj, e, &e->sec[i]);
	if (!out->n)
		out->ident = 0;
	return out->status;
}

/* ---- the swap -------------------------------------------------------------------- */

uint64_t kgenome_endian_apply(uint8_t *buf, uint64_t n, const struct kgenome_endian_plan *p)
{
	uint64_t changed = 0;
	uint32_t i;

	if (!buf || !p)
		return 0;
	for (i = 0; i < p->n; i++) {
		const struct kgenome_endian_span *s = &p->v[i];
		uint32_t es = lay_size(s->lay);
		uint64_t k;

		if (s->off >= n || s->len > n - s->off)
			continue;       /* a plan for a longer object: nothing is cut in half */
		if (s->lay <= KGENOME_ENDIAN_L_W8) {
			/* The common case, by the unit and without the field loop. */
			for (k = 0; k + es <= s->len; k += es)
				changed += unit_swap(buf + s->off + k, es);
		} else {
			for (k = 0; k + es <= s->len; k += es)
				changed += entry_swap(buf + s->off + k, s->lay);
		}
	}
	if (p->ident && n > 5u && (buf[5] == 1u || buf[5] == 2u)) {
		buf[5] = (uint8_t)(3u - buf[5]);
		changed++;
	}
	return changed;
}

void kgenome_endian_range(uint8_t *dst, const uint8_t *src, uint64_t src_n,
			  uint64_t off, uint64_t len, const struct kgenome_endian_plan *p)
{
	uint32_t lo, hi, i;

	if (!dst || !src || off >= src_n)
		return;
	if (len > src_n - off)
		len = src_n - off;
	memcpy(dst, src + off, (size_t)len);
	if (!p)
		return;
	/* First span that ends past `off`. */
	lo = 0;
	hi = p->n;
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2u;

		if (p->v[mid].off + p->v[mid].len <= off)
			lo = mid + 1u;
		else
			hi = mid;
	}
	for (i = lo; i < p->n && p->v[i].off < off + len; i++) {
		const struct kgenome_endian_span *s = &p->v[i];
		uint32_t es = lay_size(s->lay);
		uint64_t first, e, k;

		if (s->off >= src_n || s->len > src_n - s->off)
			continue;
		/* The entries that touch the range: from the one holding `off`. */
		first = off > s->off ? s->off + ((off - s->off) / es) * es : s->off;
		e = s->off + s->len;
		for (k = first; k < e && k < off + len; k += es) {
			uint8_t sc[64];
			uint64_t a, b;

			memcpy(sc, src + k, es);
			if (s->lay <= KGENOME_ENDIAN_L_W8) {
				uint32_t x, y;

				for (x = 0, y = es - 1u; x < y; x++, y--) {
					uint8_t t = sc[x];

					sc[x] = sc[y];
					sc[y] = t;
				}
			} else {
				(void)entry_swap(sc, s->lay);
			}
			for (a = k > off ? k : off, b = k + es < off + len ? k + es : off + len;
			     a < b; a++)
				dst[a - off] = sc[a - k];
		}
	}
	if (p->ident && off <= 5u && off + len > 5u && (src[5] == 1u || src[5] == 2u))
		dst[5 - off] = (uint8_t)(3u - src[5]);
}

void kgenome_endian_describe(struct kgenome_elf_info *info, const struct kgenome_endian_plan *p)
{
	if (info && p && p->ident)
		info->elf_data = info->elf_data == KGENOME_ELFDATA_BE ? KGENOME_ELFDATA_LE
								      : KGENOME_ELFDATA_BE;
}
