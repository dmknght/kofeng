/*
 * pe_image.c - the structure of a PE: headers, sections, data directories,
 * claims, and the import walk (kgenome_pe_imports, kgenome_pe_imptab).
 *
 * The BODY of what libkofeng/analyzers/parsers/binaries/pe/pe_parse.c was. What
 * stayed there is the engine side: the scan-region partition (pe_resolve_scan),
 * the names for tools, and kof_pe_parse, the adapter that calls
 * kgenome_pe_image_parse and attaches the partition. Nothing here includes the
 * engine. The original file comment follows, unchanged.
 */

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
 *   - "could not be determined" is a value. KGENOME_BROKEN, never a guess.
 *   - the parser does not refuse. It describes what it recovered and what was
 *     wrong, because refusing goes blind on the inputs worth looking at.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_image.h"
#include "clr_image.h"
#include <rangelist.h>


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
	case 0x014c: return KGENOME_ARCH_X86;
	case 0x8664: return KGENOME_ARCH_X86_64;
	case 0x01c0:
	case 0x01c2:
	case 0x01c4: return KGENOME_ARCH_ARM;
	case 0xaa64: return KGENOME_ARCH_ARM64;
	case 0x5032: return KGENOME_ARCH_RISCV32;
	case 0x5064: return KGENOME_ARCH_RISCV64;
	/* Every MIPS machine PE ever named is 32 bit. */
	case 0x0166:
	case 0x0266:
	case 0x0366:
	case 0x0466: return KGENOME_ARCH_MIPS;
	case 0x01f0:
	case 0x01f2: return KGENOME_ARCH_PPC;
	default:     return KGENOME_ARCH_OTHER;
	}
}

uint32_t kgenome_pe_sec_perm(uint32_t ch)
{
	uint32_t p = 0;

	if (ch & SCN_MEM_EXECUTE)
		p |= KGENOME_PE_PERM_X;
	if (ch & SCN_MEM_WRITE)
		p |= KGENOME_PE_PERM_W;
	if (ch & SCN_MEM_READ)
		p |= KGENOME_PE_PERM_R;
	return p;
}

/*
 * A section holds code if the loader will execute it: MEM_EXECUTE, and nothing
 * else. This used to be MEM_EXECUTE or CNT_CODE, "because a linker occasionally
 * does the reverse" of a packer, which clears CNT_CODE and keeps MEM_EXECUTE.
 * The reverse was measured over 8798 PEs and it is not code: 56 sections in 52
 * files have CNT_CODE without MEM_EXECUTE. 43 are discardable (characteristics
 * 0x42000020 / 0x42000030) - the examples read were 8 KB .reloc sections of
 * entropy 3.9-4.3, relocation data a linker mislabelled - and the sampled
 * others include an 800 KB all-zero RW section. None can be run as loaded, so
 * counting them made relocation tables part of CODE for rules and walks.
 * The other direction is real - 219 sections in 115 files are executable
 * without CNT_CODE (UPX1) - and stays code.
 */
int kgenome_pe_sec_is_code(const struct kgenome_pe_sec *s)
{
	return (s->perm & KGENOME_PE_PERM_X) != 0;
}

const struct kgenome_pe_sec *kgenome_pe_sec_at_off(const struct kgenome_pe_info *p,
					       uint64_t off)
{
	uint32_t i;

	for (i = 0; i < p->sec_count; i++) {
		const struct kgenome_pe_sec *s = &p->sec[i];

		if (s->file_size && off >= s->file_off &&
		    off - s->file_off < s->file_size)
			return s;
	}
	return NULL;
}

/* The declared raw bytes, clipped. See pe.h for why this is not the claim. */
uint64_t kgenome_pe_sec_extent(const struct kgenome_pe_sec *s, uint64_t obj_size,
			   uint64_t *off)
{
	*off = s->file_off;
	return kof_clip_len(obj_size, s->file_off, s->file_size);
}

/*
 * FileAlignment, or zero if the file's value cannot be one.
 *
 * The spec allows 512 to 65536 and requires a power of two. A value outside that
 * is not something to work around, it is something not to compute with: every
 * check below that rounds by it would otherwise produce a number derived from an
 * attacker's arithmetic and then be compared against reality.
 */
static uint64_t usable_file_align(const struct kgenome_pe_info *p)
{
	uint64_t a = p->file_align;

	if (a < 512 || a > 65536 || (a & (a - 1)))
		return 0;
	return a;
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

static void read_sections(kof_buf file, struct kgenome_pe_info *p, uint64_t sectab)
{
	uint64_t align = usable_file_align(p);
	uint32_t i;

	for (i = 0; i < p->nsec; i++) {
		uint64_t base = kof_sat_add(sectab, (uint64_t)i * SECHDR_SIZE);
		uint32_t vsize = 0, vaddr = 0, rsize = 0, raddr = 0, ch = 0;
		struct kgenome_pe_sec *s;
		uint8_t raw[8];
		uint32_t k;

		/* nsec is clamped before this runs, so this cannot trip today.
		 * It is here because the clamp and this write are in different
		 * functions: the day someone moves or relaxes one, the bound that
		 * matters should be the one next to the store. */
		if (p->sec_count >= KGENOME_PE_MAX_SECTIONS) {
			p->anomalies |= KGENOME_PE_ANOM_NSEC_CLAMPED;
			break;
		}
		s = &p->sec[p->sec_count];

		if (!kof_in_range(file, base, SECHDR_SIZE)) {
			p->anomalies |= KGENOME_PE_ANOM_SECTAB_PAST_EOF;
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
			p->anomalies |= KGENOME_PE_ANOM_SECNAME_OBJFORM;

		s->mem_size        = vsize;
		s->mem_rva         = vaddr;
		s->file_size       = rsize;
		s->file_off        = raddr;
		s->characteristics = ch;
		s->perm            = kgenome_pe_sec_perm(ch);

		if (rsize && !kof_in_range(file, raddr, rsize)) {
			p->anomalies |= KGENOME_PE_ANOM_SEC_PAST_EOF;
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
				p->anomalies |= KGENOME_PE_ANOM_SEC_RAW_GT_VIRT;
		}
		if (rsize == 0 && vsize)
			p->anomalies |= KGENOME_PE_ANOM_SEC_ZERO_RAW;
		if ((s->perm & KGENOME_PE_PERM_W) && (s->perm & KGENOME_PE_PERM_X))
			p->anomalies |= KGENOME_PE_ANOM_SEC_WRITE_EXEC;

		p->sec_count++;
	}
}

/* Tags outside the section index space, so a settled claim says what it was. */
#define HDR_TAG (KGENOME_PE_MAX_SECTIONS)
#define RES_TAG (KGENOME_PE_MAX_SECTIONS + 1)

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
static void resolve_resource(struct kgenome_pe_info *p, uint64_t obj_size)
{
	uint64_t rva, len, off;

	p->res_off = p->res_len = 0;
	if (p->n_dirs <= KGENOME_PE_DIR_RESOURCE)
		return;
	rva = p->dir[KGENOME_PE_DIR_RESOURCE].rva;
	len = p->dir[KGENOME_PE_DIR_RESOURCE].size;
	if (!rva || !len)
		return;

	off = kgenome_pe_rva_to_off(p, rva);
	if (off == KGENOME_BROKEN || off >= obj_size)
		return;
	if (len > obj_size - off)
		len = obj_size - off;
	p->res_off = off;
	p->res_len = len;
}

/*
 * THE CLI HEADER, when this image is managed code.
 *
 * Resolved the same way the resource directory is - through the section table,
 * bounds checked, and left at zero when anything does not add up. A directory
 * that points outside the file is a claim the file cannot back, and following
 * it would hand a caller a range that is not there.
 *
 * The metadata version string comes from the metadata root the CLI header
 * points at: magic "BSJB", then two version words, then a length-prefixed
 * string. It is read here rather than left to a caller because reaching it
 * means two more RVA resolutions, which is exactly the work a parser exists to
 * have done once.
 */
static void resolve_clr(struct kgenome_pe_info *p, kof_buf file, uint64_t obj_size)
{
	uint64_t rva, len, off, mroot;
	uint32_t tmp32 = 0, vlen = 0;
	uint16_t tmp16 = 0;

	p->clr_off = p->clr_len = 0;
	p->clr_version[0] = '\0';
	if (p->n_dirs <= KGENOME_PE_DIR_COM_DESCRIPTOR)
		return;
	rva = p->dir[KGENOME_PE_DIR_COM_DESCRIPTOR].rva;
	len = p->dir[KGENOME_PE_DIR_COM_DESCRIPTOR].size;
	if (!rva || !len)
		return;
	off = kgenome_pe_rva_to_off(p, rva);
	if (off == KGENOME_BROKEN || off >= obj_size)
		return;
	if (len > obj_size - off)
		len = obj_size - off;
	p->clr_off = off;
	p->clr_len = len;

	/* cb, MajorRuntimeVersion, MinorRuntimeVersion, MetaData(rva,size),
	 * Flags, EntryPointToken - the first twenty bytes of the CLI header. */
	if (kof_rd_u16(file, off + 4, 0, &tmp16)) p->clr_major = tmp16;
	if (kof_rd_u16(file, off + 6, 0, &tmp16)) p->clr_minor = tmp16;
	if (kof_rd_u32(file, off + 16, 0, &tmp32)) p->clr_flags = tmp32;
	if (kof_rd_u32(file, off + 20, 0, &tmp32)) p->clr_entry_token = tmp32;

	if (!kof_rd_u32(file, off + 8, 0, &tmp32) || !tmp32)
		return;
	mroot = kgenome_pe_rva_to_off(p, tmp32);
	if (mroot == KGENOME_BROKEN || mroot >= obj_size)
		return;
	/* "BSJB", then two uint16 versions, a reserved uint32, then the
	 * length-prefixed version string. */
	if (!kof_rd_u32(file, mroot, 0, &tmp32) || tmp32 != 0x424a5342u)
		return;
	if (!kof_rd_u32(file, mroot + 12, 0, &vlen) || !vlen)
		return;
	if (vlen > sizeof p->clr_version - 1u)
		vlen = (uint32_t)(sizeof p->clr_version - 1u);
	if (mroot + 16u + vlen > obj_size)
		return;
	memcpy(p->clr_version, file.p + mroot + 16u, vlen);
	p->clr_version[vlen] = '\0';
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
static uint64_t settle_claims(struct kgenome_pe_info *p, uint64_t obj_size)
{
	struct kof_claim c[KGENOME_PE_MAX_SECTIONS + 2];
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

	/*
	 * WHICH PAIR OF NUMBERS A SECTION OWNS ITS BYTES BY.
	 *
	 * The same section states both - where it is in the file and where the
	 * loader puts it - and which one is true of THESE bytes is not something
	 * the header knows. The caller said; see enum kgenome_pe_layout.
	 *
	 * The mapped case also stops skipping a section with no raw data. A .bss
	 * has SizeOfRawData 0 and VirtualSize of megabytes, and in memory those
	 * megabytes exist, are zero, and are writable - so they are bytes this
	 * object has and something must own them, or the partition has a hole
	 * exactly where an unpacker likes to write.
	 */
	/*
	 * THE .NET HEAPS ARE NOT CLAIMANTS HERE, and the reason is a property of
	 * settling rather than a decision about metadata.
	 *
	 * kof_rl_settle resolves a collision by trimming the front of whichever
	 * claimant starts later, which cannot express a claimant that sits
	 * STRICTLY INSIDE another - and that is exactly where a compiler puts
	 * the metadata: in the middle of .text, IL method bodies in front of it.
	 * Settled, .text reached the bytes first and every heap came back empty,
	 * and the heaps were then inside CODE as well as inside themselves.
	 *
	 * They are taken out of the sections at RESOLVE time instead, where a
	 * range can become two. See kof_rl_subtract and pe_resolve_scan.
	 */
	for (i = 0; i < p->sec_count && n < cap; i++) {
		uint64_t off, len;

		if (kgenome_pe_is_mapped(p)) {
			off = p->sec[i].mem_rva;
			len = p->sec[i].mem_size;
		} else {
			off = p->sec[i].file_off;
			len = p->sec[i].file_size;
		}
		if (!len)
			continue;
		c[n].off = off;
		c[n].len = len;
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
				p->anomalies |= KGENOME_PE_ANOM_RSRC_UNALIGNED;
				p->res_off = c[i].got_off;
				p->res_len = c[i].got_len;
			}
		} else if (c[i].tag < KGENOME_PE_MAX_SECTIONS) {
			if (trimmed && c[i].got_len && !by_resource)
				p->anomalies |= KGENOME_PE_ANOM_SEC_OVERLAP;
			p->sec[c[i].tag].claim_off = c[i].got_off;
			p->sec[c[i].tag].claim_len = c[i].got_len;
		}
		if (e > end)
			end = e;
	}
	return end;
}

static void resolve_entry(struct kgenome_pe_info *p, struct kgenome_obj *obj)
{
	uint32_t i;

	p->entry_sec  = p->sec_count;
	p->entry_perm = 0;
	obj->entry_off = KGENOME_BROKEN;

	if (p->entry_rva == 0) {
		p->anomalies |= KGENOME_PE_ANOM_ENTRY_ZERO;
		return;
	}
	for (i = 0; i < p->sec_count; i++) {
		const struct kgenome_pe_sec *s = &p->sec[i];
		uint64_t span = s->mem_size > s->file_size ? s->mem_size
							   : s->file_size;
		if (p->entry_rva < s->mem_rva || p->entry_rva - s->mem_rva >= span)
			continue;
		p->entry_sec  = i;
		p->entry_perm = s->perm;
		if (!kgenome_pe_sec_is_code(s))
			p->anomalies |= KGENOME_PE_ANOM_ENTRY_NOT_EXEC;
		if (p->entry_rva - s->mem_rva >= s->file_size)
			p->anomalies |= KGENOME_PE_ANOM_ENTRY_ZEROFILL;
		else
			obj->entry_off = s->file_off + (p->entry_rva - s->mem_rva);
		return;
	}
	p->anomalies |= KGENOME_PE_ANOM_ENTRY_UNMAPPED;
}

int kgenome_pe_sniff(kof_buf file)
{
	uint16_t mz;
	uint32_t lfanew;

	if (!kof_rd_u16(file, 0, 0, &mz) || mz != KGENOME_PE_DOS_MAGIC)
		return 0;
	if (!kof_rd_u32(file, DOS_LFANEW, 0, &lfanew))
		return 0;
	if (!kof_in_range(file, lfanew, 4))
		return 0;
	return memcmp(file.p + lfanew, "PE\0\0", 4) == 0;
}

/*
 * THE FIRST FOUR CHECKS BELOW CANNOT FAIL THROUGH THE SCANNER, ON PURPOSE.
 *
 * kgenome_pe_sniff already requires all four - the MZ, a readable e_lfanew, that
 * offset in range, and "PE\0\0" at it - and nothing in this engine calls parse
 * without sniffing first. So MZ_MISSING, LFANEW_UNREADABLE, LFANEW_PAST_EOF and
 * BAD_PE_SIG are set on paths a scan never walks.
 *
 * They stay because this is an exported function and an SDK consumer may call
 * it directly on bytes nothing sniffed; a parser that reads a header it has not
 * checked is the bug those checks exist to prevent.
 *
 * What is worth knowing is the consequence: the unit fuzzer lists those bits
 * under "PE never raised", which reads like a gap in the tests and is not one -
 * it is arithmetic. Measured while chasing exactly that: 2500 corpus files and
 * 1080 crafted near-PE files, and not one reached a parse that then failed. If
 * the sniff is ever loosened, these become reachable and the anomalies they set
 * are dropped by every caller, because a parse returning 0 takes its half
 * filled view with it. That would then be worth plumbing out; today it is not.
 */
/*
 * RVA to offset, for the .NET reader, which cannot do this itself: the answer
 * comes out of the section table and differs between a file and a mapped image.
 * See kgenome_pe_rva_to_off and enum kgenome_pe_layout.
 */
static uint64_t pe_rva_thunk(const void *user, uint64_t rva)
{
	return kgenome_pe_rva_to_off((const struct kgenome_pe_info *)user, rva);
}

int kgenome_pe_image_parse(kof_buf file, struct kgenome_pe_info *info,
		       struct kgenome_obj *obj)
{
	uint64_t nt, opt, sectab, dirbase, last_end;
	uint16_t mz = 0, magic = 0;
	uint32_t lfanew32 = 0, tmp32;
	uint32_t i;
	int is64;
	/*
	 * The one field of this view the caller owns, saved across the wipe.
	 *
	 * The memset is right - every other field is this parser's answer and a
	 * view is reused across objects - but `layout` is an INPUT, and clearing
	 * it would make every declared mapped image parse as a file and resolve
	 * its regions to the wrong bytes. Read it, wipe, put it back.
	 */
	uint32_t layout, origin;

	/*
	 * THE VIEW IS REQUIRED, AND SAYING SO IS THE POINT.
	 *
	 * The two reads below were written "info ? info->x : 0" and the memset
	 * on the next line dereferenced it anyway - a guard that promised a
	 * NULL was tolerated and then broke that promise one line later, which
	 * is worse than no guard: a caller reading the first line would believe
	 * it. Every parser in the table takes a view it must fill, kof_elf_parse
	 * does not test for one, and the thunks always pass the engine's. So
	 * this refuses instead, which is the same contract said honestly.
	 */
	if (!info || !obj)
		return 0;
	/* The caller-owned fields, saved across the wipe: `layout` is an INPUT,
	 * and clearing it would make every declared mapped image parse as a
	 * file and resolve its regions to the wrong bytes - see above and
	 * kgenome_pe_info.mem_origin. */
	layout = info->layout;
	origin = info->mem_origin;

	memset(info, 0, sizeof *info);
	info->version = KGENOME_PE_INFO_VERSION;
	info->layout  = layout == KGENOME_PE_LAYOUT_MAPPED ? KGENOME_PE_LAYOUT_MAPPED
						       : KGENOME_PE_LAYOUT_FILE;
	/*
	 * ONLY MEANINGFUL FOR A MAPPED IMAGE. A file-layout parse that
	 * inherited an origin would be claiming something about bytes that came
	 * off a disk, which is the shape of the bug the sniff path's memset was
	 * added to close.
	 */
	info->mem_origin = (info->layout == KGENOME_PE_LAYOUT_MAPPED) ? origin : 0u;

	obj->obj_size    = file.n;
	obj->entry_off   = KGENOME_NA;
	obj->arch        = KGENOME_ARCH_ANY;
	obj->file_header = 0;

	if (!kof_rd_u16(file, 0, 0, &mz) || mz != KGENOME_PE_DOS_MAGIC) {
		info->anomalies |= KGENOME_PE_ANOM_BAD_MZ;
		return 0;
	}
	if (!kof_rd_u32(file, DOS_LFANEW, 0, &lfanew32)) {
		info->anomalies |= KGENOME_PE_ANOM_TRUNCATED_HEADER;
		return 0;
	}
	nt = lfanew32;
	if (!kof_in_range(file, nt, 4 + COFF_SIZE)) {
		info->anomalies |= KGENOME_PE_ANOM_LFANEW_PAST_EOF;
		return 0;
	}
	if (memcmp(file.p + nt, "PE\0\0", 4) != 0) {
		info->anomalies |= KGENOME_PE_ANOM_BAD_PE_SIG;
		return 0;
	}

	info->valid  = 1;
	info->lfanew = nt;
	info->stub_len = nt > DOS_HDR_SIZE ? nt - DOS_HDR_SIZE : 0;
	if (info->stub_len > STUB_PLAUSIBLE_MAX)
		info->anomalies |= KGENOME_PE_ANOM_STUB_OVERSIZED;
	if (!stub_is_standard(file, nt))
		info->anomalies |= KGENOME_PE_ANOM_STUB_NONSTANDARD;

	/* COFF header. */
	kof_rd_u16(file, nt + 4 + 0,  0, &info->machine);
	kof_rd_u16(file, nt + 4 + 2,  0, &info->nsec_claimed);
	kof_rd_u32(file, nt + 4 + 4,  0, &info->timestamp);
	kof_rd_u16(file, nt + 4 + 16, 0, &info->opt_size);
	kof_rd_u16(file, nt + 4 + 18, 0, &info->characteristics);

	obj->format      = KGENOME_FMT_PE;
	obj->file_header = info;
	obj->arch        = (uint8_t)arch_from_machine(info->machine);

	info->nsec = info->nsec_claimed;
	if (info->nsec == 0)
		info->anomalies |= KGENOME_PE_ANOM_NSEC_ZERO;
	if (info->nsec > KGENOME_PE_MAX_SECTIONS) {
		info->nsec = KGENOME_PE_MAX_SECTIONS;
		info->anomalies |= KGENOME_PE_ANOM_NSEC_CLAMPED;
	}

	/* Optional header. Its size is declared, so it is used to find the section
	 * table but never to bound a read: each field below is bounds checked. */
	opt = nt + 4 + COFF_SIZE;
	if (!kof_rd_u16(file, opt, 0, &magic)) {
		info->anomalies |= KGENOME_PE_ANOM_TRUNCATED_HEADER;
		magic = 0;
	}
	info->opt_magic = magic;
	is64 = (magic == OPT_MAGIC_PE32P);
	info->pe32_plus = (uint8_t)is64;
	if (magic != OPT_MAGIC_PE32 && magic != OPT_MAGIC_PE32P)
		info->anomalies |= KGENOME_PE_ANOM_BAD_OPT_MAGIC;
	if (info->opt_size < (is64 ? 112u : 96u))
		info->anomalies |= KGENOME_PE_ANOM_OPTSIZE_ODD;

	/* The linker's own version, two bytes above the sizes - see the note on
	 * the field. A claim, not a measurement. */
	{
		uint8_t lv = 0;

		if (kof_rd_u8(file, opt + 2, &lv)) info->linker_major = lv;
		if (kof_rd_u8(file, opt + 3, &lv)) info->linker_minor = lv;
	}
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
	 * Here rather than beside obj->format above, because the subsystem is read
	 * from the optional header and that has only just happened - setting it
	 * earlier would file every driver as whatever a zeroed field says.
	 *
	 * Subsystem before the DLL characteristic: a driver carries both, so testing
	 * the flag first would make every driver read as a library.
	 */
	obj->subtype = info->subsystem == KGENOME_PE_SUBSYS_NATIVE ? KGENOME_PE_SYS :
		       (info->characteristics & KGENOME_PE_CHAR_DLL) ? KGENOME_PE_DLL :
		       KGENOME_PE_EXE;

	if (kof_rd_u32(file, opt + (is64 ? 108 : 92), 0, &tmp32))
		info->n_dirs = tmp32;
	if (info->n_dirs != KGENOME_PE_DIR_COUNT)
		info->anomalies |= KGENOME_PE_ANOM_DIR_COUNT_ODD;
	if (info->n_dirs > KGENOME_PE_DIR_COUNT)
		info->n_dirs = KGENOME_PE_DIR_COUNT;

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
		info->anomalies |= KGENOME_PE_ANOM_SIZEOFHDR_ODD;

	read_sections(file, info, sectab);
	resolve_resource(info, file.n);
	resolve_clr(info, file, file.n);
	/*
	 * The heaps, if this is a managed image. After resolve_clr because that
	 * is what found the runtime header, and before settle_claims because
	 * the heaps are claimants - see the note there.
	 */
	if (info->clr_off)
		(void)kgenome_clr_read(file, info->clr_off, pe_rva_thunk, info,
				   &info->clr);
	last_end = settle_claims(info, file.n);
	resolve_entry(info, obj);

	/*
	 * The certificate table is the one directory whose address field is a file
	 * offset rather than an RVA. Resolving it here means no caller has to know
	 * that, and getting it wrong once would put a signature blob in the middle
	 * of RVA space.
	 */
	if (info->n_dirs > KGENOME_PE_DIR_SECURITY && !kgenome_pe_is_mapped(info)) {
		uint64_t co = info->dir[KGENOME_PE_DIR_SECURITY].rva;
		uint64_t cn = info->dir[KGENOME_PE_DIR_SECURITY].size;

		if (cn) {
			uint64_t lim = kof_sat_add(co, cn);

			if (!kof_in_range(file, co, cn)) {
				info->anomalies |= KGENOME_PE_ANOM_CERT_PAST_EOF;
				lim = file.n;
			}
			/* Only past everything else. A certificate directory
			 * pointing into a section is a claim on bytes that
			 * already have an owner, and honouring it would put the
			 * same offset in two regions. */
			if (co < last_end) {
				if (co < lim)
					info->anomalies |= KGENOME_PE_ANOM_CERT_PAST_EOF;
			} else if (co < lim) {
				info->cert_off = co;
				info->cert_len = lim - co;
				last_end = lim;
			}
		}
	}

	/*
	 * Overlay: past everything any structure claimed, which settle_claims and
	 * the certificate above have already accumulated.
	 *
	 * A MAPPED IMAGE HAS NONE, and the tail past its last section is not one.
	 * An overlay is bytes appended to a FILE; the loader does not map them,
	 * so what sits past the last section in memory is the alignment slack the
	 * loader zero-filled. Calling that an overlay would put a region that
	 * means "appended payload" over a region that means "nothing", and every
	 * rule written for the first would run against the second. It is left to
	 * UNCLAIMED, which is what it honestly is - and which is still scanned,
	 * because UNCLAIMED is the complement and something writing code into
	 * that slack is precisely the case worth catching.
	 */
	if (last_end < file.n && !kgenome_pe_is_mapped(info)) {
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
			/* NOT kgenome_pe_sec_is_code: SizeOfCode is what the
			 * LINKER counted, and it counts by CNT_CODE. */
			if (info->sec[i].characteristics &
			    (SCN_MEM_EXECUTE | SCN_CNT_CODE))
				code_raw = kof_sat_add(code_raw, info->sec[i].file_size);
		if (info->size_of_code && code_raw &&
		    info->size_of_code > code_raw)
			info->anomalies |= KGENOME_PE_ANOM_SUMMARY_MISMATCH;
	}

	/* The region resolver is NOT set here: the region partition is the engine's,
	 * attached by the adapter kof_pe_parse in pe_parse.c. */
	return 1;
}

/*
 * ---- THE IMPORT DIRECTORY, WALKED ON DEMAND -------------------------------
 *
 * See the note in pe_parse.h, and the longer one in elf_parse.h for why these
 * walkers live with the parser at all. Nothing below knows what any name
 * means.
 *
 * THERE USED TO BE TWO OF THESE. pe_sym.c walked the directory to build the
 * KSYM block and the chain detector walked it again to find which slot
 * carries which capability, and the two had drifted: one stopped after 64
 * DLLs and the other after 256, one ended the table on two zero fields and
 * the other on three, one reported imports by ordinal and the other dropped
 * them. Neither disagreement was a decision. This is the walk, once, with
 * the more tolerant reading of each.
 */
#define IMP_DESC_LEN   20u    /* one IMAGE_IMPORT_DESCRIPTOR                */
#define IMP_ORIG_THUNK  0u    /* 4  OriginalFirstThunk - the name table     */
#define IMP_DLL_NAME   12u    /* 4  RVA of the library's name               */
#define IMP_FIRST_THUNK 16u   /* 4  FirstThunk - the IAT, the slots         */

/* A NUL-terminated name at a file offset, into the caller's buffer. Zero when
 * nothing could be read, so a caller can tell an empty name from a refused
 * one. */
static int imp_name_at(kof_buf f, uint64_t at, char *dst, uint32_t dstn)
{
	uint32_t q;

	if (at == KGENOME_BROKEN || !at)
		return 0;
	for (q = 0; q + 1u < dstn; q++) {
		uint8_t c8 = 0;

		if (!kof_rd_u8(f, at + q, &c8) || !c8)
			break;
		dst[q] = (char)c8;
	}
	dst[q] = 0;
	return q != 0;
}

uint32_t kgenome_pe_imports(kof_buf f, const struct kgenome_pe_info *p,
			kgenome_pe_import_fn fn, void *user,
			enum kgenome_status *status)
{
	uint64_t d, thunks_left;
	uint32_t w, k, n = 0;

	if (status)
		*status = KGENOME_OK;
	if (!f.p || !p || !p->valid || !fn)
		return 0;
	if (!p->dir[KGENOME_PE_DIR_IMPORT].rva)
		return 0;
	d = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_IMPORT].rva);
	if (d == KGENOME_BROKEN || !d)
		return 0;
	w = p->pe32_plus ? 8u : 4u;
	/*
	 * THE TOTAL THUNK BUDGET: the file's size over the pointer width. Every
	 * thunk the walk reads is a pointer-sized word of the file, so an import
	 * directory whose tables are distinct cannot hold more of them than this;
	 * only tables that overlap can, and for those it is the DoS bound - the work
	 * of the walk is at most one read per thunk of the budget plus one name per
	 * descriptor, and the descriptors are read from the file, 20 bytes each.
	 * The per-descriptor loop has no count of its own for that reason: it ends
	 * at the terminator or at the end of the file.
	 */
	thunks_left = f.n / w;

	for (k = 0;; k++) {
		uint64_t desc = d + (uint64_t)k * IMP_DESC_LEN, tbl;
		uint32_t orig = 0, first = 0, dllrva = 0, t;
		char dll[64];

		if (desc + IMP_DESC_LEN > f.n)
			break;
		if (!kof_rd_u32(f, desc + IMP_ORIG_THUNK,  0, &orig) ||
		    !kof_rd_u32(f, desc + IMP_DLL_NAME,    0, &dllrva) ||
		    !kof_rd_u32(f, desc + IMP_FIRST_THUNK, 0, &first))
			break;
		/*
		 * An all-zero descriptor ends the table - tested on the three
		 * fields that matter rather than on the whole struct, because
		 * a descriptor with only a timestamp left over is still the
		 * end.
		 */
		if (!orig && !first && !dllrva)
			break;
		if (!imp_name_at(f, kgenome_pe_rva_to_off(p, dllrva), dll,
				 sizeof dll))
			dll[0] = 0;
		/*
		 * NO FirstThunk, NO SLOT ADDRESSES.
		 *
		 * The names can come from either table and OriginalFirstThunk
		 * is preferred, but the ADDRESS reported is always
		 * image_base + FirstThunk + t*w, because the slot a call goes
		 * through is FirstThunk's. A descriptor naming only the other
		 * one made that arithmetic image_base + 0 + t*w - addresses
		 * in the DOS header - and every one of them would be handed
		 * out as the slot of a real import, on a shape a file chooses
		 * freely.
		 */
		if (!first)
			continue;
		tbl = kgenome_pe_rva_to_off(p, orig ? orig : first);
		if (tbl == KGENOME_BROKEN || !tbl)
			continue;
		for (t = 0;; t++) {
			uint64_t te = tbl + (uint64_t)t * w, val = 0;
			uint64_t slot = p->image_base + first +
					(uint64_t)t * w;
			uint32_t lo = 0;
			uint64_t noff = 0;
			char nm[64];

			if (p->pe32_plus) {
				if (!kof_rd_u64(f, te, 0, &val))
					break;
			} else {
				if (!kof_rd_u32(f, te, 0, &lo))
					break;
				val = lo;
			}
			if (!val)
				break;               /* end of this DLL */
			if (!thunks_left) {
				/* A thunk that exists and is not read: said, and the walk
				 * ends - every later thunk is past the same budget. */
				if (status)
					*status = KGENOME_TRUNCATED;
				return n;
			}
			thunks_left--;
			/*
			 * The top bit means "by ordinal", and the ordinal is
			 * the low sixteen. Tested on the right bit for the
			 * width: 0x80000000 for PE32 and
			 * 0x8000000000000000 for PE32+, which is why the two
			 * are not one test.
			 */
			if (val & (p->pe32_plus ? 0x8000000000000000ull
						: 0x80000000ull)) {
				fn(user, slot, dll, 0,
				   (uint32_t)(val & 0xffffu), 0);
				n++;
				continue;
			}
			/* An IMAGE_IMPORT_BY_NAME is a hint word and then the
			 * string, so the name is two bytes in - and the two
			 * are added to the OFFSET after it has been checked,
			 * because KGENOME_BROKEN plus two is a number that looks
			 * like an address. */
			{
				uint64_t ho = kgenome_pe_rva_to_off(p, val);

				if (ho == KGENOME_BROKEN || !ho)
					continue;
				if (!imp_name_at(f, ho + 2u, nm, sizeof nm))
					continue;
				noff = ho + 2u;
			}
			fn(user, slot, dll, nm, 0, noff);
			n++;
		}
	}
	return n;
}

/* The export directory, IMAGE_EXPORT_DIRECTORY: the only place that knows its
 * field offsets, as the descriptor offsets above are for the imports. */
#define EXP_N_NAMES      24u   /* 4  NumberOfNames                         */
#define EXP_FUNCS        28u   /* 4  AddressOfFunctions                    */
#define EXP_NAMES        32u   /* 4  AddressOfNames                        */
#define EXP_ORDS         36u   /* 4  AddressOfNameOrdinals                 */

/*
 * How many exported names one walk reports. NumberOfNames is a field the file
 * writes and a hostile one claims as many as it likes, so the walk is bounded and
 * `status` says KGENOME_TRUNCATED when it was cut - the bound is the DoS bound,
 * not a statement about the file.
 */
#define EXP_NAMES_MAX 4096u

uint32_t kgenome_pe_exports(kof_buf f, const struct kgenome_pe_info *p,
			kgenome_pe_export_fn fn, void *user,
			enum kgenome_status *status)
{
	uint64_t d;
	uint32_t n_names = 0, a_names = 0, a_ords = 0, a_funcs = 0, i, n = 0;

	if (status)
		*status = KGENOME_OK;
	if (!f.p || !p || !p->valid || !fn)
		return 0;
	d = kgenome_pe_rva_to_off(p, p->dir[KGENOME_PE_DIR_EXPORT].rva);
	if (!p->dir[KGENOME_PE_DIR_EXPORT].rva || !d)
		return 0;
	if (!kof_rd_u32(f, d + EXP_N_NAMES, 0, &n_names) ||
	    !kof_rd_u32(f, d + EXP_NAMES,   0, &a_names) ||
	    !kof_rd_u32(f, d + EXP_ORDS,    0, &a_ords)  ||
	    !kof_rd_u32(f, d + EXP_FUNCS,   0, &a_funcs))
		return 0;
	if (n_names > EXP_NAMES_MAX) {
		n_names = EXP_NAMES_MAX;
		if (status)
			*status = KGENOME_TRUNCATED;
	}
	for (i = 0; i < n_names; i++) {
		uint64_t no = kgenome_pe_rva_to_off(p, a_names) + (uint64_t)i * 4u;
		uint32_t nrva = 0, frva = 0;
		uint16_t ord = 0;

		if (!a_names || !kof_rd_u32(f, no, 0, &nrva))
			break;
		/* The RVA comes through the ordinal table, which is what maps a
		 * name to its slot in AddressOfFunctions. Skipped rather than
		 * guessed when either table is missing: a value of zero would
		 * read as "at the image base". */
		if (a_ords && a_funcs &&
		    kof_rd_u16(f, kgenome_pe_rva_to_off(p, a_ords) +
				  (uint64_t)i * 2u, 0, &ord))
			(void)kof_rd_u32(f, kgenome_pe_rva_to_off(p, a_funcs) +
					    (uint64_t)ord * 4u, 0, &frva);
		n++;
		if (!fn(user, kgenome_pe_rva_to_off(p, nrva), frva))
			break;
	}
	return n;
}

static void imptab_add(void *user, uint64_t slot, const char *dll,
		       const char *name, uint32_t ordinal, uint64_t nameoff)
{
	struct kgenome_pe_imptab *t = user;
	struct kgenome_pe_imp *e;

	(void)name;
	if (t->status == KGENOME_NOMEM)
		return;
	/* A new library only when the name changes: the walk reports the
	 * entries of a descriptor together. */
	if (!t->n_dll || strncmp(t->dll[t->n_dll - 1u], dll,
				 KGENOME_PE_IMP_DLLLEN - 1u)) {
		if (t->n_dll == t->cap_dll) {
			uint32_t nc = t->cap_dll ? t->cap_dll * 2u : 8u;
			void *nv = realloc(t->dll, (size_t)nc * sizeof *t->dll);

			if (!nv) {
				t->status = KGENOME_NOMEM;
				return;
			}
			t->dll = nv;
			t->cap_dll = nc;
		}
		snprintf(t->dll[t->n_dll], KGENOME_PE_IMP_DLLLEN, "%s", dll);
		t->n_dll++;
	}
	if (t->n == t->cap) {
		uint32_t nc = t->cap ? t->cap * 2u : 256u;
		void *nv = realloc(t->v, (size_t)nc * sizeof *t->v);

		if (!nv) {
			t->status = KGENOME_NOMEM;
			return;
		}
		t->v = nv;
		t->cap = nc;
	}
	e = &t->v[t->n++];
	e->slot = slot;
	e->nameoff = nameoff;
	e->ordinal = ordinal;
	e->dll = t->n_dll - 1u;
}

void kgenome_pe_imptab_build(kof_buf f, const struct kgenome_pe_info *p,
			 struct kgenome_pe_imptab *t)
{
	memset(t, 0, sizeof *t);
	t->from = f;
	{
		enum kgenome_status st;

		kgenome_pe_imports(f, p, imptab_add, t, &st);
		t->status = kgenome_status_merge(t->status, st);
	}
}

int kgenome_pe_imptab_is_of(const struct kgenome_pe_imptab *t, kof_buf f)
{
	return t && t->from.p == f.p && t->from.n == f.n;
}

void kgenome_pe_imptab_free(struct kgenome_pe_imptab *t)
{
	if (!t)
		return;
	free(t->v);
	free(t->dll);
	memset(t, 0, sizeof *t);
}

uint32_t kgenome_pe_imp_name(kof_buf f, const struct kgenome_pe_imp *e, char *dst,
			 uint32_t dstn)
{
	if (!dstn)
		return 0;
	dst[0] = 0;
	if (!e || !e->nameoff || !imp_name_at(f, e->nameoff, dst, dstn))
		return 0;
	return (uint32_t)strlen(dst);
}
