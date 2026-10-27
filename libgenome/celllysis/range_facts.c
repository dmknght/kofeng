/*
 * range_facts.c - kgenome_range_xref_build and kgenome_range_facts. See range_facts.h for what is answered and bounded.
 */
#include <stdlib.h>
#include <string.h>

#include <kofentropy.h>
#include <celllysis/range_facts.h>
#include <celllysis/celllysis.h>
#include <celllysis/decode.h>
#include <genotype/image/elf_image.h>
#include <genotype/image/pe_image.h>

/*
 * THE SHAPE THRESHOLDS. Each says which measurement chose it; the measurement is the table the change that added this file
 * reported (the range facts of ordinary data variables, tables, text and code of /bin/ls and of Linux malware samples).
 *
 *   TEXT_PCT     90  of the bytes are printable ASCII or tab, CR, LF. A string table or a banner is 95-100%; a blob of code or
 *                    pointers is under 40% (measured on the sets above), so anything between is not text.
 *   TABLE_PCT    75  of the pointer-sized words are small integers (below 64 Ki) or share the high bytes of the first address
 *                    word (v >> 24). A jump table, a vtable or a GOT is 90-100%; x86-64 code read as 8-byte words is under 5%.
 *   CODE_PCT     90  of the bytes decode as instructions. Real code of the architecture is 97-100%, but the x86 decoder is dense:
 *                    measured on the dynamic linking data of a small PIE (.dynstr, .gnu.hash, .rela.*, .eh_frame, .note.*) 92-100%
 *                    of THESE bytes decode, so the share alone does not separate code from data. Two more measures do:
 *   FLOW         >=1 decoded instruction transfers control (call, jump, conditional jump, loop, ret, system call): code that
 *                    does anything has one; the data above decodes into runs of `add [rax],al` with none (measured 0 of 9
 *                    ordinary data ranges with one, against every real function and every payload sample).
 *   TEXT_MAX     60  printable bytes (0x20-0x7e, tab, CR, LF) in a code-like range are at most this share. x86 decodes ASCII
 *                    strings as code (the letters p-~ are conditional jumps): measured, the .rodata strings of /bin/ls, /bin/cat
 *                    and two samples are 71-92% printable and 94-98% "decoded", with 19-32% control transfers, exactly like code.
 *                    Real code is 12-32% printable (.text 22-29%, .plt 18-32%, 50% for an 8-byte stub).
 *   ZERO_MAX     25  zero bytes at most this share. .eh_frame decodes at 93-96% with 2-6% control transfers and is 33-52% zero
 *                    bytes; code is 3-16% zero (.text 3-16%, .plt 19-25%).
 *   FIXED-WIDTH ISAs (ARM, AArch64, MIPS): the decoders accept almost every aligned word, so the decode share proves nothing
 *                    there. Measured on a static ARM binary (0c8e384b...): its 14 KB .rodata decoded 100% with control transfers
 *                    and a system call, and 20 ordinary variables (ctype tables, a 20-byte character table, a table of powers
 *                    of ten) read code-like. On these a range is code-like only when CODE refers to it (a count from the
 *                    reference map); the sweep tracks x86 only, so today that is never, and the class is MIXED. The decode
 *                    share is still reported.
 *   JUNK_PCT     20  of the decoded instructions at most may be of a kind ordinary code almost never uses (privileged, undefined,
 *                    x87, string operations, an `int` other than 0x80, iret, a move to a special register). Real code of
 *                    /bin/ls and the samples is under 6%; data read as x86 is 25-60%.
 *                    RANDOM is tested first, which is what keeps encrypted data from reading as code.
 *   RANDOM_CENTI 750 bits a byte times 100, and only for 256 bytes or more (fewer bytes cannot reach 8 bits: n bytes give at
 *                    most log2(n)). Compressed and encrypted data is 7.8-8.0; machine code is 5.2-6.6; text 4.0-5.2.
 */
#define KGENOME_RANGE_TEXT_PCT      90u
#define KGENOME_RANGE_TABLE_PCT     75u
#define KGENOME_RANGE_CODE_PCT      90u
#define KGENOME_RANGE_JUNK_PCT      20u
#define KGENOME_RANGE_TEXT_MAX      60u
#define KGENOME_RANGE_ZERO_MAX      25u
#define KGENOME_RANGE_RANDOM_CENTI  750u
#define KGENOME_RANGE_RANDOM_MIN    256u
#define KGENOME_RANGE_TABLE_MIN     4u     /* words: fewer is not a table */

#define PT_OFF_ELF_REL 1u                  /* e_type ET_REL: its words are unrelocated, no pointer count */

/* ---- the reference map -------------------------------------------------------------------------------------- */

static int arch_is_x86(unsigned arch)
{
	return arch == KGENOME_ARCH_X86 || arch == KGENOME_ARCH_X86_64;
}

static uint64_t rd_word(const uint8_t *p, unsigned wd, int be)
{
	uint64_t v = 0;
	unsigned j;

	for (j = 0; j < wd; j++)
		v |= (uint64_t)p[be ? wd - 1u - j : j] << (8u * j);
	return v;
}

/* Name the addresses startup code has to the map, as the map asks (xref.h): the entry, every executable section that is not
 * .text, and what .init_array and .fini_array hold. */
static void startup_elf(struct kgenome_xref *map, const struct kgenome_elf_info *e, kof_buf f)
{
	uint32_t i, wd = e->elf_class == KGENOME_ELFCLASS_64 ? 8u : 4u;
	int be = e->elf_data == KGENOME_ELFDATA_BE;

	if (e->entry_addr)
		kgenome_xref_startup(map, e->entry_addr);
	for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
		const struct kgenome_elf_sec *sec = &e->sec[i];
		uint64_t k, have;

		if (kgenome_elf_sec_is_code(sec) && strcmp(sec->name, ".text") != 0)
			kgenome_xref_startup(map, sec->mem_addr);
		if (sec->type != 14u && sec->type != 15u)
			continue;           /* INIT_ARRAY, FINI_ARRAY */
		have = kof_clip_len(f.n, sec->file_off, sec->file_size);
		for (k = 0; k + wd <= have; k += wd)
			if (!kgenome_xref_startup(map, rd_word(f.p + sec->file_off + k, wd, be)))
				break;
	}
}

/* One run of the sweep over code at file offset `at`, `have` bytes, running at `va`. */
static void sweep_run(struct kgenome_xref *map, unsigned arch, kof_buf f, uint64_t at, uint64_t have, uint64_t va)
{
	uint64_t pos, end;

	kgenome_xref_begin(map, arch);
	for (pos = at, end = at + have; pos < end; ) {
		struct kgenome_cell_insn ci;
		uint64_t rem = end - pos;
		uint32_t len = kgenome_cell_decode(arch, 0, f.p + pos, rem > UINT32_MAX ? UINT32_MAX : (uint32_t)rem,
						   va + (pos - at), &ci);

		if (len) {
			ci.at = pos;
			kgenome_xref_feed(map, &ci);
			pos += len;
		} else {
			kgenome_xref_feed(map, NULL);       /* data in the code */
			pos++;
		}
	}
}

enum kgenome_status kgenome_range_xref_build(const struct kgenome_obj *obj, kof_buf file, const struct kgenome_budget *budget,
					     struct kgenome_xref **out)
{
	uint64_t left, total = 0;
	struct kgenome_xref *map;
	uint32_t i;
	int cut = 0, caller = budget && budget->max_steps;

	*out = NULL;
	if (!obj || !obj->file_header || (obj->format != KGENOME_FMT_ELF && obj->format != KGENOME_FMT_PE))
		return KGENOME_BAD_INPUT;
	if (!arch_is_x86(obj->arch))
		return KGENOME_UNSUPPORTED;
	left = caller ? budget->max_steps : KGENOME_XREF_MAX;
	map = kgenome_xref_new();
	if (!map)
		return KGENOME_NOMEM;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		if (!e->valid) {
			kgenome_xref_free(map);
			return KGENOME_BAD_INPUT;
		}
		startup_elf(map, e, file);
		for (i = 0; i < e->sec_count && i < KGENOME_ELF_MAX_SECTIONS; i++) {
			const struct kgenome_elf_sec *sec = &e->sec[i];
			uint64_t at, have;

			if (!kgenome_elf_sec_is_code(sec) || !(have = kgenome_elf_sec_extent(sec, file.n, &at)))
				continue;
			total += have;
			if (have > left) {
				have = left;
				cut = 1;
			}
			left -= have;
			sweep_run(map, obj->arch, file, at, have, sec->mem_addr);
		}
	} else {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		if (!p->valid) {
			kgenome_xref_free(map);
			return KGENOME_BAD_INPUT;
		}
		kgenome_xref_startup(map, p->image_base + p->entry_rva);
		for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++) {
			const struct kgenome_pe_sec *sec = &p->sec[i];
			uint64_t at, have;

			if (!kgenome_pe_sec_is_code(sec) || !(have = kgenome_pe_sec_extent(sec, file.n, &at)))
				continue;
			total += have;
			if (have > left) {
				have = left;
				cut = 1;
			}
			left -= have;
			sweep_run(map, obj->arch, file, at, have, p->image_base + sec->mem_rva);
		}
	}
	if (cut || total > (caller ? budget->max_steps : (uint64_t)KGENOME_XREF_MAX) || kgenome_xref_full(map)) {
		*out = map;
		return caller ? KGENOME_OVER_BUDGET : KGENOME_TRUNCATED;
	}
	*out = map;
	return KGENOME_OK;
}

/* ---- the facts of one range --------------------------------------------------------------------------------- */

static int arch_decodes(unsigned arch)
{
	return arch_is_x86(arch) || arch == KGENOME_ARCH_ARM || arch == KGENOME_ARCH_ARM64 || arch == KGENOME_ARCH_MIPS ||
	       arch == KGENOME_ARCH_MIPS64;
}

/* A kind of instruction ordinary code almost never uses: see JUNK_PCT. */
static int is_junk(const struct kgenome_cell_insn *ci)
{
	switch (ci->op) {
	case KGENOME_CELL_PRIV: case KGENOME_CELL_UD: case KGENOME_CELL_FPU: case KGENOME_CELL_STRING:
	case KGENOME_CELL_IRET: case KGENOME_CELL_MOV_SPECIAL:
		return 1;
	case KGENOME_CELL_INT:
		return !(ci->n_op >= 1u && ci->o[0].kind == KGENOME_CELL_O_IMM && ci->o[0].imm == 0x80u);
	default:
		return 0;
	}
}

/* An instruction that transfers control (FLOW above). */
static int is_flow(const struct kgenome_cell_insn *ci)
{
	switch (ci->op) {
	case KGENOME_CELL_CALL: case KGENOME_CELL_JMP: case KGENOME_CELL_JCC: case KGENOME_CELL_LOOP: case KGENOME_CELL_RET:
	case KGENOME_CELL_SYSCALL:
		return 1;
	default:
		return ci->op == KGENOME_CELL_INT && !is_junk(ci);
	}
}

static int is_syscall(const struct kgenome_cell_insn *ci)
{
	return ci->op == KGENOME_CELL_SYSCALL ||
	       (ci->op == KGENOME_CELL_INT && ci->n_op >= 1u && ci->o[0].kind == KGENOME_CELL_O_IMM && ci->o[0].imm == 0x80u);
}

/* A linear sweep of the range with the object's own architecture: the share of bytes in instructions, and a system call. */
static void sweep_decode(const struct kgenome_obj *obj, const uint8_t *p, uint64_t n, uint64_t va, struct kgenome_range_facts *f)
{
	uint64_t pos = 0, ok = 0;
	int be = kgenome_obj_big_endian(obj) && !kgenome_obj_code_little_endian(obj);

	while (pos < n) {
		struct kgenome_cell_insn ci;
		uint64_t rem = n - pos;
		uint32_t len = kgenome_cell_decode(obj->arch, be, p + pos, rem > UINT32_MAX ? UINT32_MAX : (uint32_t)rem,
						   va + pos, &ci);

		if (len) {
			ok += len;
			if (is_syscall(&ci))
				f->syscall = 1;
			f->insns++;
			f->flow += (uint32_t)is_flow(&ci);
			f->junk += (uint32_t)is_junk(&ci);
			pos += len;
		} else {
			pos++;
		}
	}
	f->decodes = 1;
	f->decode_pct = n ? (uint32_t)(ok * 100u / n) : 0u;
}

static unsigned word_width(const struct kgenome_obj *obj)
{
	if (obj->format == KGENOME_FMT_ELF)
		return kgenome_obj_elf(obj)->elf_class == KGENOME_ELFCLASS_64 ? 8u : 4u;
	return kgenome_obj_pe(obj)->pe32_plus ? 8u : 4u;
}

/* Repeating pointer-sized words: small integers, or addresses that share their high bytes with the first address word. */
static int looks_like_table(const struct kgenome_obj *obj, const uint8_t *p, uint64_t n)
{
	unsigned wd = word_width(obj);
	int be = kgenome_obj_big_endian(obj);
	uint64_t i, words = n / wd, good = 0, base = 0;
	int have_base = 0;

	if (words < KGENOME_RANGE_TABLE_MIN)
		return 0;
	for (i = 0; i < words; i++) {
		uint64_t v = rd_word(p + i * wd, wd, be);

		if (v < 0x10000u) {
			good++;
		} else if (!have_base) {
			have_base = 1;
			base = v >> 24;
			good++;
		} else if ((v >> 24) == base) {
			good++;
		}
	}
	return good * 100u >= words * KGENOME_RANGE_TABLE_PCT;
}

/* The byte statistics every shape rule reads: the shares of printable and of zero bytes, and whether all bytes are one. */
static int byte_stats(const uint8_t *p, uint64_t n, struct kgenome_range_facts *f)
{
	uint64_t i, text = 0, zero = 0;
	int same = 1;

	for (i = 0; i < n; i++) {
		if (p[i] != p[0])
			same = 0;
		zero += p[i] == 0;
		if ((p[i] >= 0x20u && p[i] < 0x7fu) || p[i] == '\t' || p[i] == '\r' || p[i] == '\n')
			text++;
	}
	f->text_pct = n ? (uint32_t)(text * 100u / n) : 0u;
	f->zero_pct = n ? (uint32_t)(zero * 100u / n) : 0u;
	return same && n;
}

/* ARM, AArch64 and MIPS: see FIXED-WIDTH ISAs above. */
static int fixed_width_isa(unsigned arch)
{
	return arch == KGENOME_ARCH_ARM || arch == KGENOME_ARCH_ARM64 || arch == KGENOME_ARCH_MIPS || arch == KGENOME_ARCH_MIPS64;
}

static uint32_t decide_shape(const struct kgenome_obj *obj, const uint8_t *p, uint64_t n, int same,
			     const struct kgenome_range_facts *f)
{
	if (same)
		return KGENOME_RANGE_EMPTY;
	if (n && f->text_pct >= KGENOME_RANGE_TEXT_PCT)
		return KGENOME_RANGE_TEXT;
	if (n >= KGENOME_RANGE_RANDOM_MIN && f->entropy_centi >= KGENOME_RANGE_RANDOM_CENTI)
		return KGENOME_RANGE_RANDOM;
	if (looks_like_table(obj, p, n))
		return KGENOME_RANGE_TABLE;
	if (fixed_width_isa(obj->arch) &&
	    !(f->refs_known && f->refs.call + f->refs.jump + f->refs.read + f->refs.write + f->refs.arg))
		return KGENOME_RANGE_MIXED;
	if (f->decodes && f->decode_pct >= KGENOME_RANGE_CODE_PCT && f->flow &&
	    (uint64_t)f->junk * 100u <= (uint64_t)f->insns * KGENOME_RANGE_JUNK_PCT && f->text_pct <= KGENOME_RANGE_TEXT_MAX &&
	    f->zero_pct <= KGENOME_RANGE_ZERO_MAX)
		return KGENOME_RANGE_CODE_LIKE;
	return KGENOME_RANGE_MIXED;
}

/* How many pointer-sized words of the object's non-executable image hold an address inside [va, va + size), the words of the
 * range itself not counted. Reads at most KGENOME_RANGE_PTR_SCAN bytes. */
static uint32_t count_ptrs(const struct kgenome_obj *obj, kof_buf f, uint64_t off, uint64_t size, uint64_t va, int *cut)
{
	unsigned wd = word_width(obj);
	int be = kgenome_obj_big_endian(obj);
	uint64_t left = KGENOME_RANGE_PTR_SCAN, n_ptr = 0;
	uint32_t i, n_seg;
	struct { uint64_t off, len; } seg[KGENOME_ELF_MAX_SEGMENTS > KGENOME_PE_MAX_SECTIONS ? KGENOME_ELF_MAX_SEGMENTS
									       : KGENOME_PE_MAX_SECTIONS];

	n_seg = 0;
	if (obj->format == KGENOME_FMT_ELF) {
		const struct kgenome_elf_info *e = kgenome_obj_elf(obj);

		if (e->e_type == PT_OFF_ELF_REL)
			return 0;
		for (i = 0; i < e->seg_count && i < KGENOME_ELF_MAX_SEGMENTS; i++)
			if (kgenome_elf_seg_is_load(&e->seg[i]) && !(e->seg[i].perm & KGENOME_PERM_X)) {
				seg[n_seg].off = e->seg[i].file_off;
				seg[n_seg++].len = kof_clip_len(f.n, e->seg[i].file_off, e->seg[i].file_size);
			}
	} else {
		const struct kgenome_pe_info *p = kgenome_obj_pe(obj);

		for (i = 0; i < p->sec_count && i < KGENOME_PE_MAX_SECTIONS; i++)
			if (!(p->sec[i].perm & KGENOME_PE_PERM_X)) {
				seg[n_seg].off = p->sec[i].file_off;
				seg[n_seg++].len = kof_clip_len(f.n, p->sec[i].file_off, p->sec[i].file_size);
			}
	}
	for (i = 0; i < n_seg; i++) {
		uint64_t k, len = seg[i].len;

		if (len > left) {
			len = left;
			*cut = 1;
		}
		left -= len;
		for (k = 0; k + wd <= len; k += wd) {
			uint64_t at = seg[i].off + k, v = rd_word(f.p + at, wd, be);

			if (v - va < size && !(at >= off && at - off < size) && n_ptr < 0xffffffffu)
				n_ptr++;
		}
	}
	return (uint32_t)n_ptr;
}

enum kgenome_status kgenome_range_facts(const struct kgenome_range_req *rq, struct kgenome_range_facts *f)
{
	enum kgenome_status st = KGENOME_OK;
	uint64_t n, bound, va_base;
	uint32_t hist[256];
	int ptr_cut = 0, same;

	memset(f, 0, sizeof *f);
	if (!rq->obj || !rq->obj->file_header || (rq->obj->format != KGENOME_FMT_ELF && rq->obj->format != KGENOME_FMT_PE) ||
	    rq->off >= rq->file.n || !rq->size)
		return KGENOME_BAD_INPUT;
	if (rq->budget && rq->budget->max_steps)
		bound = rq->budget->max_steps;
	else
		bound = KGENOME_RANGE_BYTES;
	n = kof_clip_len(rq->file.n, rq->off, rq->size);
	if (n > bound) {
		n = bound;
		st = rq->budget && rq->budget->max_steps ? KGENOME_OVER_BUDGET : KGENOME_TRUNCATED;
	}
	f->analysed = n;
	if (rq->xref) {
		f->refs_known = 1;
		f->refs_partial = rq->xref_status != KGENOME_OK || kgenome_xref_full(rq->xref);
		kgenome_xref_refs(rq->xref, rq->va, rq->size, &f->refs);
	}
	va_base = rq->va;
	f->refs_ptr = count_ptrs(rq->obj, rq->file, rq->off, rq->size, va_base, &ptr_cut);
	if (ptr_cut && st == KGENOME_OK)
		st = KGENOME_TRUNCATED;
	if (arch_decodes(rq->obj->arch))
		sweep_decode(rq->obj, rq->file.p + rq->off, n, rq->va, f);
	same = byte_stats(rq->file.p + rq->off, n, f);
	memset(hist, 0, sizeof hist);
	kentropy_count(hist, rq->file.p + rq->off, n);
	f->entropy_centi = kentropy_hist_centi(hist, n);
	f->shape = decide_shape(rq->obj, rq->file.p + rq->off, n, same, f);
	return st;
}
