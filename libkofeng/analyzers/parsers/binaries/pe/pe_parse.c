/*
 * pe_parse.c - the engine side of the PE parser.
 *
 * The structural parse (headers, sections, directories, claims, the import
 * walk) lives in libgenome/genotype/image/pe_image.c. What stays here is what only the
 * engine has: the scan-region partition (pe_resolve_scan, the KOF_SCAN_PE_*
 * masks over the object) and the names for tools. The notes on how the parse
 * behaves are with its body.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_parse.h"
#include "../../../genome_obj.h"
#include <genotype/image/clr_image.h>
#include <rangelist.h>

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
	const struct kgenome_pe_info *p = (const struct kgenome_pe_info *)ctx->file_header;
	struct kof_rlist l;
	uint32_t i;

	if (!p || !p->valid || !out || max_out == 0)
		return 0;

	kof_rl_init(&l, out, max_out);

	if (mask & KGENOME_SCAN_PE_HEADERS)
		kof_rl_add(&l, ctx->obj_size, 0, p->header_end);

	if (mask & KGENOME_SCAN_PE_CODE)
		for (i = 0; i < p->sec_count; i++)
			if (kgenome_pe_sec_is_code(&p->sec[i]))
				kof_rl_add(&l, ctx->obj_size, p->sec[i].claim_off,
					   p->sec[i].claim_len);

	if (mask & KGENOME_SCAN_PE_DATA)
		for (i = 0; i < p->sec_count; i++)
			if (!kgenome_pe_sec_is_code(&p->sec[i]))
				kof_rl_add(&l, ctx->obj_size, p->sec[i].claim_off,
					   p->sec[i].claim_len);

	if (mask & KGENOME_SCAN_PE_RESOURCE)
		kof_rl_add(&l, ctx->obj_size, p->res_off, p->res_len);

	if (mask & KGENOME_SCAN_PE_SIGNATURE)
		kof_rl_add(&l, ctx->obj_size, p->cert_off, p->cert_len);

	if (mask & KGENOME_SCAN_PE_OVERLAY)
		kof_rl_add(&l, ctx->obj_size, p->overlay_off, p->overlay_len);

	/*
	 * THE .NET HEAPS BELONG TO NOBODY ELSE.
	 *
	 * Taken out of whatever was added above - which in practice is the code
	 * section, because that is where a compiler puts them - before they are
	 * added as themselves. Unconditional on the mask: a caller asking only
	 * for CODE must not be handed the string heaps under that name, whether
	 * or not it also asked for them.
	 *
	 * What is left of .text after this is the part that really is code: the
	 * IL method bodies in front of the metadata, and the native stub.
	 */
	if (kgenome_clr_present(&p->clr)) {
		struct kof_range cut[KGENOME_CLR_CLAIM_MAX];
		uint32_t cn = kgenome_clr_claims(&p->clr, cut, KGENOME_CLR_CLAIM_MAX);

		if (cn)
			kof_rl_subtract(&l, cut, cn);
	}

	if (mask & KGENOME_SCAN_CLR_CLAIMED)
		kgenome_clr_add_ranges(&p->clr, mask, &l, ctx->obj_size);

	if (mask & KGENOME_SCAN_PE_UNCLAIMED) {
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
		/* Twice the sections, because kof_rl_subtract splits a
		 * section the metadata sits inside into two, plus the .NET
		 * claims themselves and the four singletons. */
		struct kof_range cv[KGENOME_PE_MAX_SECTIONS * 2u +
				    KGENOME_CLR_CLAIM_MAX + 4u];
		struct kof_rlist c;

		kof_rl_init(&c, cv, (uint32_t)(sizeof cv / sizeof cv[0]));
		c.n = pe_resolve_scan(ctx, KGENOME_SCAN_PE_CLAIMED, cv, c.cap);
		kof_rl_complement(&l, &c, ctx->obj_size);
	}
	return kof_rl_normalise(&l);
}


/*
 * THE ADAPTER, A DELIBERATE BOUNDARY AND NOT A STRAY WRAPPER.
 *
 * The signature callers use is kept here; the parse is kgenome_pe_image_parse in
 * libgenome. The one thing added is the resolver, because the partition of the
 * object into scan regions is the engine's and the genome must not know it.
 * Attached only when the object is PE, as before: a failed identification
 * leaves ctx->resolve_scan zero.
 */
int kof_pe_parse(kof_buf file, struct kgenome_pe_info *info, struct kof_obj_ctx *ctx)
{
	struct kgenome_obj obj;
	int ok;

	if (!info || !ctx)
		return 0;
	/* Cleared on the way in, as the genome parse used to: a failed
	 * identification must not leave a resolver from a previous file. */
	ctx->resolve_scan = 0;
	kof_genome_obj(ctx, &obj);
	ok = kgenome_pe_image_parse(file, info, &obj);
	kof_genome_obj_store(ctx, &obj);
	if (ok)
		ctx->resolve_scan = pe_resolve_scan;
	return ok;
}

/* ---- names, for tools ------------------------------------------------------- */


#define X_BIT(b)  (KGENOME_##b),
#define X_CASE(b) case KGENOME_##b: return "KOF_" #b;

const uint32_t kof_pe_region_bits[] = { PE_REGIONS(X_BIT) };
_Static_assert(sizeof kof_pe_region_bits / sizeof kof_pe_region_bits[0] ==
	       KOF_PE_REGION_COUNT, "region list and its count disagree");

const char *kof_pe_region_name(uint32_t bit)
{
	/* The .NET bits are not PE's to name: they mean the same in every format
	 * that hosts an assembly, so one namer answers for all of them. */
	const char *clr = kgenome_clr_region_name(bit);

	if (clr)
		return clr;
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


	_Static_assert(sizeof n / sizeof n[0] == KGENOME_PE_ANOM_COUNT,
		       "anomaly name table and its count disagree");
	return index < sizeof n / sizeof n[0] ? n[index] : 0;
}
