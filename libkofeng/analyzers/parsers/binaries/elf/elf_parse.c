/*
 * elf_parse.c - the engine side of the ELF parser.
 *
 * The structural parse (headers, segments, sections, claims, the symbol,
 * import and relocation walks) lives in libgenome/genotype/image/elf_image.c. What stays
 * here is what only the engine has: the scan-region partition
 * (elf_resolve_scan, the KOF_SCAN_ELF_* masks over the object) and the names
 * for tools. The notes on how the parse behaves are with its body.
 */

#include "elf_parse.h"
#include "../../../genome_obj.h"
#include <rangelist.h>

#include <stdlib.h>
#include <string.h>

/* The one spelling of these is in <image/elf_image.h>. */
#define PT_LOAD		KGENOME_ELF_PT_LOAD
#define SHT_NULL	KGENOME_ELF_SHT_NULL
#define SHT_NOBITS	KGENOME_ELF_SHT_NOBITS
#define SHF_ALLOC	KGENOME_ELF_SHF_ALLOC

/*
 * Resolve a mask to ranges. Reached through ctx->resolve_scan, so the host never
 * learns that any of this is ELF specific.
 *
 * Recursive for one region only: UNCLAIMED asks for the complement of everything
 * else. C needs no forward declaration for that.
 */
static uint32_t elf_resolve_scan(const struct kof_obj_ctx *ctx, uint32_t mask,
				 struct kof_range *out, uint32_t max_out)
{
	const struct kgenome_elf_info *e = (const struct kgenome_elf_info *)ctx->file_header;
	struct kof_rlist l;
	uint32_t i;

	if (!e || !e->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);

	if (mask & KGENOME_SCAN_ELF_HEADERS) {
		kof_rl_add(&l, ctx->obj_size, e->hdr_claim_off, e->hdr_claim_len);
		kof_rl_add(&l, ctx->obj_size, e->shtab_claim_off,
			   e->shtab_claim_len);
	}

	/*
	 * Code and data come from the segments, and from the sections when there are
	 * no segments.
	 *
	 * Both describe the same file and the segment is normally the better source -
	 * it is what a loader acts on, and a section name is a string somebody chose.
	 * But a relocatable object has no segments at all, and then the section flags
	 * are not a second opinion, they are the only one. SHF_EXECINSTR is the same
	 * fact PF_X carries, stated by the other table.
	 */
	if (mask & KGENOME_SCAN_ELF_CODE) {
		for (i = 0; i < e->seg_count; i++)
			if (kgenome_elf_seg_is_code(&e->seg[i]))
				kof_rl_add(&l, ctx->obj_size, e->seg[i].claim_off,
					   e->seg[i].claim_len);
		if (!e->seg_count)
			for (i = 0; i < e->sec_count; i++)
				if (kgenome_elf_sec_is_code(&e->sec[i]) &&
				    (e->sec[i].flags & SHF_ALLOC))
					kof_rl_add(&l, ctx->obj_size,
						   e->sec[i].claim_off,
						   e->sec[i].claim_len);
	}

	if (mask & KGENOME_SCAN_ELF_DATA) {
		for (i = 0; i < e->seg_count; i++)
			if (e->seg[i].type == PT_LOAD &&
			    !(e->seg[i].perm & KGENOME_PERM_X))
				kof_rl_add(&l, ctx->obj_size, e->seg[i].claim_off,
					   e->seg[i].claim_len);
		if (!e->seg_count)
			for (i = 0; i < e->sec_count; i++)
				if ((e->sec[i].flags & SHF_ALLOC) &&
				    !kgenome_elf_sec_is_code(&e->sec[i]))
					kof_rl_add(&l, ctx->obj_size,
						   e->sec[i].claim_off,
						   e->sec[i].claim_len);
	}

	if (mask & KGENOME_SCAN_ELF_NOLOAD)
		for (i = 0; i < e->sec_count; i++)
			if (e->sec[i].type != SHT_NULL &&
			    e->sec[i].type != SHT_NOBITS &&
			    !(e->sec[i].flags & SHF_ALLOC))
				kof_rl_add(&l, ctx->obj_size, e->sec[i].claim_off,
					   e->sec[i].claim_len);

	if (mask & KGENOME_SCAN_ELF_UNCLAIMED) {
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
		struct kof_range cv[KGENOME_ELF_MAX_SEGMENTS + KGENOME_ELF_MAX_SECTIONS + 2];
		struct kof_rlist c;

		kof_rl_init(&c, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		c.n = elf_resolve_scan(ctx, KGENOME_SCAN_ELF_CLAIMED, cv, c.cap);
		kof_rl_complement(&l, &c, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}

/*
 * THE ADAPTER, A DELIBERATE BOUNDARY AND NOT A STRAY WRAPPER.
 *
 * The signature callers use is kept here; the parse is kgenome_elf_image_parse in
 * libgenome. The one thing added is the resolver, because the partition of the
 * object into scan regions is the engine's and the genome must not know it.
 * Attached only when the object is ELF, as before: a failed identification
 * leaves ctx->resolve_scan zero.
 */
int kof_elf_parse(kof_buf file, struct kgenome_elf_info *info,
		  struct kof_obj_ctx *ctx)
{
	struct kgenome_obj obj;
	int ok;

	/* Cleared on the way in: a failed identification must not leave a resolver
	 * from a previous file on a reused context. */
	ctx->resolve_scan = 0;
	kof_genome_obj(ctx, &obj);
	ok = kgenome_elf_image_parse(file, info, &obj);
	kof_genome_obj_store(ctx, &obj);
	if (ok)
		ctx->resolve_scan = elf_resolve_scan;
	return ok;
}

/* ---- names, for tools ------------------------------------------------------- */


#define X_BIT(b)  (KGENOME_##b),
#define X_CASE(b) case KGENOME_##b: return "KOF_" #b;

const uint32_t kof_elf_region_bits[] = { ELF_REGIONS(X_BIT) };
_Static_assert(sizeof kof_elf_region_bits / sizeof kof_elf_region_bits[0] ==
	       KOF_ELF_REGION_COUNT, "region list and its count disagree");

const char *kof_elf_region_name(uint32_t bit)
{
	switch (bit) {
	ELF_REGIONS(X_CASE)
	default: return 0;
	}
}

#undef X_BIT
#undef X_CASE

const char *kof_elf_anomaly_name(unsigned index)
{
	static const char *const n[] = {
		"BAD_MAGIC", "BAD_CLASS", "BAD_ENDIAN", "BAD_VERSION",
		"TRUNCATED_HEADER", "PHOFF_PAST_EOF", "PHENTSIZE_ODD",
		"PHNUM_CLAMPED", "SHOFF_PAST_EOF", "SHNUM_CLAMPED", "SEG_PAST_EOF",
		"SEG_FILESZ_GT_MEM", "SEG_OVERLAP", "NO_LOAD_SEGMENT", "ENTRY_ZERO",
		"ENTRY_UNMAPPED", "ENTRY_ZEROFILL", "ENTRY_NOT_EXEC",
		"SHENTSIZE_ODD", "SHSTRNDX_BAD", "SEC_PAST_EOF", "SECNAME_UNREAD",
		"SECNAME_TRUNC", "SECTAB_MISSING"
	};


	_Static_assert(sizeof n / sizeof n[0] == KGENOME_ELF_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
