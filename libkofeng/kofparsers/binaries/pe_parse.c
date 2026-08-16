/*
 * pe_parse.c - recover what a PE image says about itself.
 *
 * Every value here comes out of the file, so every value is hostile until it has
 * been bounded. The rules, which are the same ones the ELF collector follows and
 * which are worth stating because there will be more parsers:
 *
 *   - a declared length is never used as a bound. The bound is computed and the
 *     declared value is compared against it, with disagreement recorded.
 *   - a declared count never drives iteration. It is clamped, and the clamp is
 *     itself an anomaly, so a forged count costs a bit rather than a loop.
 *   - offset arithmetic is 64 bit with saturation, even for 32 bit fields:
 *     PointerToRawData and SizeOfRawData both at 0xffffffff must not wrap.
 *   - "could not be determined" is a value. KOF_BROKEN, never a guess.
 *   - the parser does not refuse. It describes what it recovered and what was
 *     wrong, because refusing goes blind on the inputs worth looking at.
 */

#include <string.h>

#include "pe_parse.h"
#include "../rangelist.h"

/* Offsets within the structures, so the reads below read as the spec does. */
#define DOS_LFANEW      0x3c
#define DOS_HDR_SIZE    0x40
#define COFF_SIZE       20
#define SECHDR_SIZE     40

#define OPT_MAGIC_PE32  0x010b
#define OPT_MAGIC_PE32P 0x020b

/* IMAGE_SCN_* */
#define SCN_CNT_CODE      0x00000020u
#define SCN_CNT_INIT_DATA 0x00000040u
#define SCN_MEM_EXECUTE   0x20000000u
#define SCN_MEM_READ      0x40000000u
#define SCN_MEM_WRITE     0x80000000u

/*
 * The gap between the DOS header and the NT headers, past which it stops looking
 * like a stub and starts looking like storage.
 *
 * NOT measured: the corpus here is eight files, where this gap runs 56 to 184
 * bytes. 1024 is chosen to be far enough above that a normal linker cannot reach
 * it, and it should be revisited against a real corpus rather than trusted.
 */
#define STUB_PLAUSIBLE_MAX 1024

static uint32_t arch_from_machine(uint16_t m)
{
	switch (m) {
	case 0x014c: return KOF_ARCH_X86;
	case 0x8664: return KOF_ARCH_X86_64;
	case 0x01c0:
	case 0x01c2:
	case 0x01c4: return KOF_ARCH_ARM;
	case 0xaa64: return KOF_ARCH_ARM64;
	case 0x5032: return KOF_ARCH_RISCV32;
	case 0x5064: return KOF_ARCH_RISCV64;
	/* Every MIPS machine PE ever named is 32 bit. */
	case 0x0166:
	case 0x0266:
	case 0x0366:
	case 0x0466: return KOF_ARCH_MIPS;
	case 0x01f0:
	case 0x01f2: return KOF_ARCH_PPC;
	default:     return KOF_ARCH_OTHER;
	}
}

static uint32_t sec_perm(uint32_t ch)
{
	uint32_t p = 0;

	if (ch & SCN_MEM_EXECUTE)
		p |= KOF_PE_PERM_X;
	if (ch & SCN_MEM_WRITE)
		p |= KOF_PE_PERM_W;
	if (ch & SCN_MEM_READ)
		p |= KOF_PE_PERM_R;
	return p;
}

/* A section holds code if the loader will execute it, or if the linker said so.
 * Either alone is enough: a packer clears CNT_CODE and keeps MEM_EXECUTE, and a
 * linker occasionally does the reverse. */
static int sec_is_code(const struct kof_pe_sec *s)
{
	return (s->characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE)) != 0;
}

/*
 * FileAlignment, or zero if the file's value cannot be one.
 *
 * The spec allows 512 to 65536 and requires a power of two. A value outside that
 * is not something to work around, it is something not to compute with: every
 * check below that rounds by it would otherwise produce a number derived from an
 * attacker's arithmetic and then be compared against reality.
 */
static uint64_t usable_file_align(const struct kof_pe_info *p)
{
	uint64_t a = p->file_align;

	if (a < 512 || a > 65536 || (a & (a - 1)))
		return 0;
	return a;
}

/* ---- region resolution ------------------------------------------------------ */

/*
 * Resolve a mask to ranges. Reached through ctx->resolve_scan, so the host never
 * learns that any of this is PE specific.
 *
 * Recursive for one region only: UNCLAIMED asks for the complement of everything
 * else. C needs no forward declaration for that.
 */
static uint32_t pe_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				struct kof_range *out, uint32_t max_out)
{
	const struct kof_pe_info *p = (const struct kof_pe_info *)ctx->file_header;
	struct kof_rlist l;
	uint32_t i;

	if (!p || !p->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);

	if (mask & KOF_SCAN_PE_HEADERS)
		kof_rl_add(&l, ctx->obj_size, 0, p->header_end);

	if (mask & KOF_SCAN_PE_CODE)
		for (i = 0; i < p->sec_count; i++)
			if (sec_is_code(&p->sec[i]))
				kof_rl_add(&l, ctx->obj_size, p->sec[i].claim_off,
					   p->sec[i].claim_len);

	if (mask & KOF_SCAN_PE_DATA)
		for (i = 0; i < p->sec_count; i++)
			if (!sec_is_code(&p->sec[i]))
				kof_rl_add(&l, ctx->obj_size, p->sec[i].claim_off,
					   p->sec[i].claim_len);

	if (mask & KOF_SCAN_PE_RESOURCE)
		kof_rl_add(&l, ctx->obj_size, p->res_off, p->res_len);

	if (mask & KOF_SCAN_PE_SIGNATURE)
		kof_rl_add(&l, ctx->obj_size, p->cert_off, p->cert_len);

	if (mask & KOF_SCAN_PE_OVERLAY)
		kof_rl_add(&l, ctx->obj_size, p->overlay_off, p->overlay_len);

	if (mask & KOF_SCAN_PE_UNCLAIMED) {
		/*
		 * The complement of every other region, obtained by asking for
		 * them.
		 *
		 * Listing the claimants again here is what this used to do, and
		 * it was a second description of the same thing: add a region,
		 * forget to add it to the list, and it silently appears in
		 * UNCLAIMED as well as in itself - two regions returning the same
		 * offset, which is exactly what the partition forbids. Asking the
		 * resolver makes UNCLAIMED the complement by construction.
		 *
		 * Scratch is needed because the claimed set has to be complete
		 * and normalised before it can be inverted, and it is larger than
		 * the result.
		 */
		struct kof_range cv[KOF_PE_MAX_SECTIONS + 3];
		struct kof_rlist c;

		kof_rl_init(&c, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		c.n = pe_resolve_scan(ctx, KOF_SCAN_PE_CLAIMED, cv, c.cap);
		kof_rl_complement(&l, &c, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

/* ---- the collector ---------------------------------------------------------- */

/*
 * The stub every mainstream linker emits announces itself. Its absence is not
 * proof of anything on its own, which is why it is an anomaly and not a verdict.
 *
 * The search window is capped rather than run to e_lfanew. e_lfanew is a 32 bit
 * field the file chooses, so a 100MB file can put the NT headers at the end and
 * turn this into a 100MB scan for a 38 byte string - per object, on the identify
 * path, before a single module has run. The standard stub puts its message in the
 * first few dozen bytes; anything that hid it further out is not the standard
 * stub, which is the answer this function exists to give.
 */
#define STUB_SEARCH_MAX 512

static int stub_is_standard(kof_buf file, uint64_t lfanew)
{
	static const char msg[] = "This program cannot be run in DOS mode";
	const uint64_t need = sizeof msg - 1;
	uint64_t i, end;

	if (lfanew <= DOS_HDR_SIZE)
		return 0;
	end = lfanew < file.n ? lfanew : file.n;
	/* In 64 bit. The obvious form of this - DOS_HDR_SIZE + STUB_SEARCH_MAX in
	 * whatever type the constants happen to be - wraps for a large cap and
	 * silently turns the whole search off, which is how a bound becomes a bug
	 * the day someone widens it. */
	if (end > (uint64_t)DOS_HDR_SIZE + STUB_SEARCH_MAX)
		end = (uint64_t)DOS_HDR_SIZE + STUB_SEARCH_MAX;
	if (end < (uint64_t)DOS_HDR_SIZE + need)
		return 0;
	for (i = DOS_HDR_SIZE; i + need <= end; i++)
		if (memcmp(file.p + i, msg, (size_t)need) == 0)
			return 1;
	return 0;
}

static void read_sections(kof_buf file, struct kof_pe_info *p, uint64_t sectab)
{
	uint64_t align = usable_file_align(p);
	uint32_t i;

	for (i = 0; i < p->nsec; i++) {
		uint64_t base = kof_sat_add(sectab, (uint64_t)i * SECHDR_SIZE);
		uint32_t vsize = 0, vaddr = 0, rsize = 0, raddr = 0, ch = 0;
		struct kof_pe_sec *s;
		uint8_t raw[8];
		uint32_t k;

		/* nsec is clamped before this runs, so this cannot trip today.
		 * It is here because the clamp and this write are in different
		 * functions: the day someone moves or relaxes one, the bound that
		 * matters should be the one next to the store. */
		if (p->sec_count >= KOF_PE_MAX_SECTIONS) {
			p->anomalies |= KOF_PE_ANOM_NSEC_CLAMPED;
			break;
		}
		s = &p->sec[p->sec_count];

		if (!kof_in_range(file, base, SECHDR_SIZE)) {
			p->anomalies |= KOF_PE_ANOM_SECTAB_PAST_EOF;
			break;
		}
		memcpy(raw, file.p + base, 8);
		kof_rd_u32(file, base + 8,  0, &vsize);
		kof_rd_u32(file, base + 12, 0, &vaddr);
		kof_rd_u32(file, base + 16, 0, &rsize);
		kof_rd_u32(file, base + 20, 0, &raddr);
		kof_rd_u32(file, base + 36, 0, &ch);

		memset(s, 0, sizeof *s);
		/* Eight bytes as written, then a terminator of our own: an image
		 * name that uses all eight carries none. Bytes are copied without
		 * interpretation - a name is evidence, and sanitising it here
		 * would lose exactly the odd ones worth seeing. */
		for (k = 0; k < 8; k++)
			s->name[k] = (char)raw[k];
		s->name[8] = 0;
		s->name_hash = kof_hash_bytes(raw, 8);
		if (raw[0] == '/')
			p->anomalies |= KOF_PE_ANOM_SECNAME_OBJFORM;

		s->mem_size        = vsize;
		s->mem_rva         = vaddr;
		s->file_size       = rsize;
		s->file_off        = raddr;
		s->characteristics = ch;
		s->perm            = sec_perm(ch);

		if (rsize && !kof_in_range(file, raddr, rsize)) {
			p->anomalies |= KOF_PE_ANOM_SEC_PAST_EOF;
			/* Keep the section but clip what it can claim, so the
			 * partition stays inside the file. */
			s->file_size = (raddr < file.n) ? file.n - raddr : 0;
		}
		/*
		 * More file bytes than the virtual size can account for, even
		 * after alignment padding.
		 *
		 * The naive form of this - raw > virtual - fired on six of eight
		 * clean files, because SizeOfRawData is rounded up to
		 * FileAlignment and VirtualSize is not, so the two differing is
		 * the normal case rather than the interesting one. What is
		 * interesting is bytes past what rounding can explain: that is
		 * content parked inside a section the loader will not map.
		 */
		if (vsize && align) {
			uint64_t explained = kof_round_up(vsize, align);
			if (rsize > explained)
				p->anomalies |= KOF_PE_ANOM_SEC_RAW_GT_VIRT;
		}
		if (rsize == 0 && vsize)
			p->anomalies |= KOF_PE_ANOM_SEC_ZERO_RAW;
		if ((s->perm & KOF_PE_PERM_W) && (s->perm & KOF_PE_PERM_X))
			p->anomalies |= KOF_PE_ANOM_SEC_WRITE_EXEC;

		p->sec_count++;
	}
}

/* Tags outside the section index space, so a settled claim says what it was. */
#define HDR_TAG (KOF_PE_MAX_SECTIONS)
#define RES_TAG (KOF_PE_MAX_SECTIONS + 1)

/*
 * The resource directory as a file range.
 *
 * Its address is an RVA like every directory except the certificate one, so it
 * needs the section table to become an offset - which is why this runs after the
 * sections are read and before ownership is settled.
 *
 * Length is clipped to what the containing section actually holds. A directory
 * declaring more than its section has is describing bytes that are not there, and
 * following it would hand a scan a range past the end of the file.
 */
static void resolve_resource(struct kof_pe_info *p, uint64_t obj_size)
{
	uint64_t rva, len, off;

	p->res_off = p->res_len = 0;
	if (p->n_dirs <= KOF_PE_DIR_RESOURCE)
		return;
	rva = p->dir[KOF_PE_DIR_RESOURCE].rva;
	len = p->dir[KOF_PE_DIR_RESOURCE].size;
	if (!rva || !len)
		return;

	off = kof_pe_rva_to_off(p, rva);
	if (off == KOF_BROKEN || off >= obj_size)
		return;
	if (len > obj_size - off)
		len = obj_size - off;
	p->res_off = off;
	p->res_len = len;
}

/*
 * Settle which bytes each structure owns.
 *
 * The regions have to be disjoint or they are not a partition, and nothing in the
 * format guarantees that: two sections may point at the same file bytes, a section
 * may start inside the headers, and the certificate directory may point anywhere
 * at all. Fuzzing found this immediately - a single flipped byte in a section
 * header was enough to make CODE and OVERLAY return the same offset.
 *
 * So ownership is decided once, here, in offset order with the earlier claimant
 * keeping the bytes. What a section declared stays in file_off and file_size for a
 * module to read; what it actually owns goes in claim_off and claim_len, and the
 * two differing sets an anomaly. Resolving each region independently and hoping
 * they did not collide is what produced the bug.
 *
 * Returns the first offset past everything claimed.
 */
static uint64_t settle_claims(struct kof_pe_info *p, uint64_t obj_size)
{
	struct kof_claim c[KOF_PE_MAX_SECTIONS + 2];
	const uint32_t cap = (uint32_t)(sizeof c / sizeof c[0]);
	uint32_t n = 0, i;
	uint64_t end = 0;

	for (i = 0; i < p->sec_count; i++)
		p->sec[i].claim_off = p->sec[i].claim_len = 0;

	/* The headers claim first and outrank a section that starts at the same
	 * offset: a section pointing into the header block is describing bytes the
	 * loader has already read as something else. */
	c[n].off = 0;
	c[n].len = p->header_end;
	c[n].rank = 0;
	c[n].tag = HDR_TAG;
	n++;

	/*
	 * The resource directory outranks the section it sits in, so that at the
	 * same offset the more specific claim takes the bytes and the section is
	 * left with the alignment tail. Measured: it starts exactly at the front
	 * of its section in every file here, which is what makes a front trim
	 * enough to separate them.
	 */
	if (p->res_len) {
		c[n].off = p->res_off;
		c[n].len = p->res_len;
		c[n].rank = 1;
		c[n].tag = RES_TAG;
		n++;
	}

	for (i = 0; i < p->sec_count && n < cap; i++) {
		if (!p->sec[i].file_size)
			continue;
		c[n].off = p->sec[i].file_off;
		c[n].len = p->sec[i].file_size;
		c[n].rank = 2;
		c[n].tag = i;
		n++;
	}

	kof_rl_settle(c, n, obj_size);

	/*
	 * kof_rl_settle leaves the array in offset order, so the claimant that
	 * trimmed a given one is simply the one before it. That matters for the
	 * anomaly: a section trimmed by the resource directory is the normal case
	 * - the directory sits at the front of its own section - while a section
	 * trimmed by another section or by the headers is a real collision.
	 *
	 * Flagging every trim was the first version and it fired on every file
	 * carrying resources, which is the same way of being useless as an anomaly
	 * that fires on half a clean corpus.
	 */
	for (i = 0; i < n; i++) {
		uint64_t e = kof_sat_add(c[i].got_off, c[i].got_len);
		int trimmed = c[i].got_len != c[i].len;
		int by_resource = i > 0 && c[i - 1].tag == RES_TAG;

		if (c[i].tag == RES_TAG) {
			/* The directory did not begin where a section does, so a
			 * section already owned the bytes. Recorded rather than
			 * worked around. */
			if (trimmed) {
				p->anomalies |= KOF_PE_ANOM_RSRC_UNALIGNED;
				p->res_off = c[i].got_off;
				p->res_len = c[i].got_len;
			}
		} else if (c[i].tag < KOF_PE_MAX_SECTIONS) {
			if (trimmed && c[i].got_len && !by_resource)
				p->anomalies |= KOF_PE_ANOM_SEC_OVERLAP;
			p->sec[c[i].tag].claim_off = c[i].got_off;
			p->sec[c[i].tag].claim_len = c[i].got_len;
		}
		if (e > end)
			end = e;
	}
	return end;
}

static void resolve_entry(struct kof_pe_info *p, struct kof_obj_ctx *ctx)
{
	uint32_t i;

	p->entry_sec  = p->sec_count;
	p->entry_perm = 0;
	ctx->entry_off = KOF_BROKEN;

	if (p->entry_rva == 0) {
		p->anomalies |= KOF_PE_ANOM_ENTRY_ZERO;
		return;
	}
	for (i = 0; i < p->sec_count; i++) {
		const struct kof_pe_sec *s = &p->sec[i];
		uint64_t span = s->mem_size > s->file_size ? s->mem_size
							   : s->file_size;
		if (p->entry_rva < s->mem_rva || p->entry_rva - s->mem_rva >= span)
			continue;
		p->entry_sec  = i;
		p->entry_perm = s->perm;
		if (!(s->perm & KOF_PE_PERM_X))
			p->anomalies |= KOF_PE_ANOM_ENTRY_NOT_EXEC;
		if (p->entry_rva - s->mem_rva >= s->file_size)
			p->anomalies |= KOF_PE_ANOM_ENTRY_ZEROFILL;
		else
			ctx->entry_off = s->file_off + (p->entry_rva - s->mem_rva);
		return;
	}
	p->anomalies |= KOF_PE_ANOM_ENTRY_UNMAPPED;
}

int kof_pe_sniff(kof_buf file)
{
	uint16_t mz;
	uint32_t lfanew;

	if (!kof_rd_u16(file, 0, 0, &mz) || mz != 0x5a4d)
		return 0;
	if (!kof_rd_u32(file, DOS_LFANEW, 0, &lfanew))
		return 0;
	if (!kof_in_range(file, lfanew, 4))
		return 0;
	return memcmp(file.p + lfanew, "PE\0\0", 4) == 0;
}

int kof_pe_parse(kof_buf file, struct kof_pe_info *info, struct kof_obj_ctx *ctx)
{
	uint64_t nt, opt, sectab, dirbase, last_end;
	uint16_t mz = 0, magic = 0;
	uint32_t lfanew32 = 0, tmp32;
	uint32_t i;
	int is64;

	memset(info, 0, sizeof *info);
	info->version = KOF_PE_INFO_VERSION;

	ctx->obj_size    = file.n;
	ctx->entry_off   = KOF_NA;
	ctx->arch        = KOF_ARCH_ANY;
	ctx->file_header = 0;
	ctx->resolve_scan = 0;

	if (!kof_rd_u16(file, 0, 0, &mz) || mz != 0x5a4d) {
		info->anomalies |= KOF_PE_ANOM_BAD_MZ;
		return 0;
	}
	if (!kof_rd_u32(file, DOS_LFANEW, 0, &lfanew32)) {
		info->anomalies |= KOF_PE_ANOM_TRUNCATED_HEADER;
		return 0;
	}
	nt = lfanew32;
	if (!kof_in_range(file, nt, 4 + COFF_SIZE)) {
		info->anomalies |= KOF_PE_ANOM_LFANEW_PAST_EOF;
		return 0;
	}
	if (memcmp(file.p + nt, "PE\0\0", 4) != 0) {
		info->anomalies |= KOF_PE_ANOM_BAD_PE_SIG;
		return 0;
	}

	info->valid  = 1;
	info->lfanew = nt;
	info->stub_len = nt > DOS_HDR_SIZE ? nt - DOS_HDR_SIZE : 0;
	if (info->stub_len > STUB_PLAUSIBLE_MAX)
		info->anomalies |= KOF_PE_ANOM_STUB_OVERSIZED;
	if (!stub_is_standard(file, nt))
		info->anomalies |= KOF_PE_ANOM_STUB_NONSTANDARD;

	/* COFF header. */
	kof_rd_u16(file, nt + 4 + 0,  0, &info->machine);
	kof_rd_u16(file, nt + 4 + 2,  0, &info->nsec_claimed);
	kof_rd_u32(file, nt + 4 + 4,  0, &info->timestamp);
	kof_rd_u16(file, nt + 4 + 16, 0, &info->opt_size);
	kof_rd_u16(file, nt + 4 + 18, 0, &info->characteristics);

	ctx->format      = KOF_FMT_PE;
	ctx->file_header = info;
	ctx->arch        = (uint8_t)arch_from_machine(info->machine);

	info->nsec = info->nsec_claimed;
	if (info->nsec == 0)
		info->anomalies |= KOF_PE_ANOM_NSEC_ZERO;
	if (info->nsec > KOF_PE_MAX_SECTIONS) {
		info->nsec = KOF_PE_MAX_SECTIONS;
		info->anomalies |= KOF_PE_ANOM_NSEC_CLAMPED;
	}

	/* Optional header. Its size is declared, so it is used to find the section
	 * table but never to bound a read: each field below is bounds checked. */
	opt = nt + 4 + COFF_SIZE;
	if (!kof_rd_u16(file, opt, 0, &magic)) {
		info->anomalies |= KOF_PE_ANOM_TRUNCATED_HEADER;
		magic = 0;
	}
	info->opt_magic = magic;
	is64 = (magic == OPT_MAGIC_PE32P);
	info->pe32_plus = (uint8_t)is64;
	if (magic != OPT_MAGIC_PE32 && magic != OPT_MAGIC_PE32P)
		info->anomalies |= KOF_PE_ANOM_BAD_OPT_MAGIC;
	if (info->opt_size < (is64 ? 112u : 96u))
		info->anomalies |= KOF_PE_ANOM_OPTSIZE_ODD;

	if (kof_rd_u32(file, opt + 4,  0, &tmp32)) info->size_of_code        = tmp32;
	if (kof_rd_u32(file, opt + 8,  0, &tmp32)) info->size_of_init_data   = tmp32;
	if (kof_rd_u32(file, opt + 12, 0, &tmp32)) info->size_of_uninit_data = tmp32;
	if (kof_rd_u32(file, opt + 16, 0, &tmp32)) info->entry_rva           = tmp32;
	if (kof_rd_u32(file, opt + 20, 0, &tmp32)) info->base_of_code        = tmp32;

	if (is64)
		kof_rd_u64(file, opt + 24, 0, &info->image_base);
	else if (kof_rd_u32(file, opt + 28, 0, &tmp32))
		info->image_base = tmp32;

	if (kof_rd_u32(file, opt + 32, 0, &tmp32)) info->section_align   = tmp32;
	if (kof_rd_u32(file, opt + 36, 0, &tmp32)) info->file_align      = tmp32;
	if (kof_rd_u32(file, opt + 56, 0, &tmp32)) info->size_of_image   = tmp32;
	if (kof_rd_u32(file, opt + 60, 0, &tmp32)) info->size_of_headers = tmp32;
	kof_rd_u16(file, opt + 68, 0, &info->subsystem);
	kof_rd_u16(file, opt + 70, 0, &info->dll_characteristics);

	/*
	 * What kind of image this is, for the prefilter.
	 *
	 * Here rather than beside ctx->format above, because the subsystem is read
	 * from the optional header and that has only just happened - setting it
	 * earlier would file every driver as whatever a zeroed field says.
	 *
	 * Subsystem before the DLL characteristic: a driver carries both, so testing
	 * the flag first would make every driver read as a library.
	 */
	ctx->subtype = info->subsystem == KOF_PE_SUBSYS_NATIVE ? KOF_PE_SYS :
		       (info->characteristics & KOF_PE_CHAR_DLL) ? KOF_PE_DLL :
		       KOF_PE_EXE;

	if (kof_rd_u32(file, opt + (is64 ? 108 : 92), 0, &tmp32))
		info->n_dirs = tmp32;
	if (info->n_dirs != KOF_PE_DIR_COUNT)
		info->anomalies |= KOF_PE_ANOM_DIR_COUNT_ODD;
	if (info->n_dirs > KOF_PE_DIR_COUNT)
		info->n_dirs = KOF_PE_DIR_COUNT;

	dirbase = opt + (is64 ? 112 : 96);
	for (i = 0; i < info->n_dirs; i++) {
		uint32_t a = 0, n = 0;
		kof_rd_u32(file, dirbase + (uint64_t)i * 8,     0, &a);
		kof_rd_u32(file, dirbase + (uint64_t)i * 8 + 4, 0, &n);
		info->dir[i].rva  = a;
		info->dir[i].size = n;
	}

	/*
	 * The section table's position comes from the declared optional header
	 * size, and the header region's end from where the table stops. That is
	 * the computed bound; SizeOfHeaders is the file's claim about the same
	 * thing, and the two disagreeing is recorded rather than resolved.
	 */
	sectab = kof_sat_add(opt, info->opt_size);
	info->header_end = kof_sat_add(sectab, (uint64_t)info->nsec * SECHDR_SIZE);
	if (info->header_end > file.n)
		info->header_end = file.n;
	/*
	 * SizeOfHeaders is rounded up to FileAlignment, so it is expected to be
	 * larger than the exact end of the section table - comparing the two for
	 * equality fired on all eight files in the corpus and said nothing.
	 *
	 * What is worth recording is the other direction: a file claiming its
	 * headers end before its own section table does. The loader maps
	 * SizeOfHeaders worth of bytes, so structures past it are structures the
	 * loader never sees, which is a way of showing one thing to a parser and
	 * another to the system.
	 */
	if (info->size_of_headers && info->size_of_headers < info->header_end)
		info->anomalies |= KOF_PE_ANOM_SIZEOFHDR_ODD;

	read_sections(file, info, sectab);
	resolve_resource(info, file.n);
	last_end = settle_claims(info, file.n);
	resolve_entry(info, ctx);

	/*
	 * The certificate table is the one directory whose address field is a file
	 * offset rather than an RVA. Resolving it here means no caller has to know
	 * that, and getting it wrong once would put a signature blob in the middle
	 * of RVA space.
	 */
	if (info->n_dirs > KOF_PE_DIR_SECURITY) {
		uint64_t co = info->dir[KOF_PE_DIR_SECURITY].rva;
		uint64_t cn = info->dir[KOF_PE_DIR_SECURITY].size;

		if (cn) {
			uint64_t lim = kof_sat_add(co, cn);

			if (!kof_in_range(file, co, cn)) {
				info->anomalies |= KOF_PE_ANOM_CERT_PAST_EOF;
				lim = file.n;
			}
			/* Only past everything else. A certificate directory
			 * pointing into a section is a claim on bytes that
			 * already have an owner, and honouring it would put the
			 * same offset in two regions. */
			if (co < last_end) {
				if (co < lim)
					info->anomalies |= KOF_PE_ANOM_CERT_PAST_EOF;
			} else if (co < lim) {
				info->cert_off = co;
				info->cert_len = lim - co;
				last_end = lim;
			}
		}
	}

	/* Overlay: past everything any structure claimed, which settle_claims and
	 * the certificate above have already accumulated. */
	if (last_end < file.n) {
		info->overlay_off = last_end;
		info->overlay_len = file.n - last_end;
	}

	/*
	 * The linker's summary against the section table. This is the only
	 * cross-check PE offers, so it is worth making: SizeOfCode is what the
	 * linker said it emitted, and the executable sections are what it actually
	 * wrote down.
	 */
	{
		uint64_t code_raw = 0;
		for (i = 0; i < info->sec_count; i++)
			if (sec_is_code(&info->sec[i]))
				code_raw = kof_sat_add(code_raw, info->sec[i].file_size);
		if (info->size_of_code && code_raw &&
		    info->size_of_code > code_raw)
			info->anomalies |= KOF_PE_ANOM_SUMMARY_MISMATCH;
	}

	ctx->resolve_scan = pe_resolve_scan;
	return 1;
}

/* ---- names, for tools ------------------------------------------------------- */

/* The regions, once: bit list and names generated from the same line each. */
#define PE_REGIONS(X)           \
	X(KOF_SCAN_PE_HEADERS)    \
	X(KOF_SCAN_PE_CODE)       \
	X(KOF_SCAN_PE_DATA)       \
	X(KOF_SCAN_PE_RESOURCE)   \
	X(KOF_SCAN_PE_SIGNATURE)  \
	X(KOF_SCAN_PE_OVERLAY)    \
	X(KOF_SCAN_PE_UNCLAIMED)

#define X_BIT(b)  (b),
#define X_CASE(b) case (b): return #b;

const uint32_t kof_pe_region_bits[] = { PE_REGIONS(X_BIT) };
_Static_assert(sizeof kof_pe_region_bits / sizeof kof_pe_region_bits[0] ==
	       KOF_PE_REGION_COUNT, "region list and its count disagree");

const char *kof_pe_region_name(uint32_t bit)
{
	switch (bit) {
	PE_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_pe_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_MZ", "LFANEW_PAST_EOF", "BAD_PE_SIG", "TRUNCATED_HEADER",
		"BAD_OPT_MAGIC", "OPTSIZE_ODD", "NSEC_ZERO", "NSEC_CLAMPED",
		"SECTAB_PAST_EOF", "SEC_PAST_EOF", "SEC_OVERLAP", "SEC_RAW_GT_VIRT",
		"SEC_ZERO_RAW", "SEC_WRITE_EXEC", "SECNAME_OBJFORM", "SIZEOFHDR_ODD",
		"ENTRY_ZERO", "ENTRY_UNMAPPED", "ENTRY_NOT_EXEC", "ENTRY_ZEROFILL",
		"CERT_PAST_EOF", "DIR_COUNT_ODD", "STUB_OVERSIZED",
		"STUB_NONSTANDARD", "SUMMARY_MISMATCH", "DEBUG_OUTSIDE_SEC",
		"RSRC_UNALIGNED"
	};


	_Static_assert(sizeof n / sizeof n[0] == KOF_PE_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
