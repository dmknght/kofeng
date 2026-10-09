/*
 * VMPROTECT, UNPACKED WITHOUT RUNNING ANYTHING.
 *
 * VMProtect is two things wearing one name. The famous half VIRTUALISES chosen
 * functions into bytecode and nothing static undoes that. The other half is an
 * ordinary PACKER: it LZMA-compresses whole sections, leaves them declared in
 * the section table with no file bytes at all, and rebuilds them at load time
 * from a small table its stub carries. That half comes apart statically, and
 * this module does that half.
 *
 * WHAT THAT IS WORTH. What comes out is the program with its code and data
 * where its own header says they are - measured on a sample here, a 3.5 MB
 * section that decompressed to exactly its VirtualSize and opens with
 * `mov [rsp+8], rbx; push rdi; sub rsp, 0x20` - so every rule scoped to code,
 * to imports or to resources runs over it. Whatever of it was virtualised is
 * still virtualised; that is a different layer and is not claimed here.
 *
 * ---- HOW IT IS LAID OUT ---------------------------------------------------
 *
 * A PACKED SECTION IS A HOLLOW ONE THAT IS NOT BSS: SizeOfRawData and
 * PointerToRawData both zero, and the uninitialised-data characteristic NOT
 * set. The second half matters - a real .bss is hollow for an honest reason
 * and has the flag to say so.
 *
 * THE TABLE. The stub carries an array of eight byte entries, one per packed
 * section: a source RVA where that section's LZMA stream begins, and the
 * destination RVA it belongs at. From VMProtect 3.9 the destination is stored
 * exclusive-ored with a key that the loader rotates left seven bits before
 * each entry, so there are no plaintext addresses to search for.
 *
 * FINDING IT ANYWAY. The destinations are the packed sections' addresses,
 * which the section table already gives - so the key can be recovered rather
 * than searched for. Seed it from the first entry against each candidate
 * section; the remaining entries then have to decrypt to the OTHER
 * destinations, each exactly once. Over five or seven entries that permutation
 * only closes on the real table. Two cheap filters come first: every source
 * RVA has to resolve to a file offset, and the byte there has to be zero,
 * which is the range coder's first byte in every LZMA stream.
 *
 * THE PROPERTIES ARE NOT ASSUMED. Immediately before the table the stub keeps
 * an {RVA, 5} pair pointing at the five LZMA property bytes it hands the
 * decoder, and the first of those is the packed lc/lp/pb byte. It is read from
 * there. Only when that pair is not present - the 3.9+ layout does not carry
 * one - does this fall back to 0x5D, which is lc=3, lp=0, pb=2, the encoder's
 * defaults and what those builds use.
 *
 * NONE OF THIS IS THIS PROJECT'S WORK. The layout, the key schedule and the
 * permutation argument are VMPStatic's (github.com/.../VMPStatic, and see
 * THIRD-PARTY.md); this is a C module against kofeng's own decoders and PE
 * writer, and the bounds are its own.
 */

#include <kofmod/kofsig.h>
#include <kofmod/pe.h>

#include <kofunpack/pe_reassemble.h>

KOF_ANALYZE_STEP(KOF_ANALYZE_UNPACK);

KOF_TARGET_FORMAT(KOF_FMT_PE);
KOF_TARGET_CONTENT("VMProtect");

/* The family a VMProtect heuristic predicts, so this is entered ahead of the
 * general pass - see KOF_HEUR_PREDICT in bases/heur/vmprotect_00.c. */
KOF_TARGET_NAME(KOF_MALTYPE_TROJAN, "VMProtect");

/* The props byte when the file carries none: lc=3, lp=0, pb=2. */
#define VMP_PROPS_DEF 0x5du
#define VMP_PROPS_MAX 224u    /* lc + 9*lp + 45*pb cannot exceed this */
#define VMP_PROPS_LEN 5u      /* what the {RVA, len} pair before the table says */
#define VMP_MIN_BLK   2u      /* one entry carries too little to tell a table
			       * from a stray pointer */
#define VMP_MAX_BLK   16u

struct vmp_tab {
	uint32_t src[VMP_MAX_BLK];
	uint32_t dst[VMP_MAX_BLK];
	uint32_t n;
	uint32_t props;       /* the LZMA props byte this file's table named */
};

static uint32_t vmp_rol(uint32_t v, unsigned n)
{
	n &= 31u;
	return n ? (uint32_t)((v << n) | (v >> (32u - n))) : v;
}

/* A section's file offset for an RVA, or 0 when nothing holds it. Zero is not
 * a valid answer here either way: no section starts at offset zero. */
static uint64_t vmp_off_of(const struct kof_pe_info *pe, uint32_t rva)
{
	uint32_t i;

	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];
		uint64_t span = s->mem_size > s->file_size
			      ? s->mem_size : s->file_size;

		if (!s->file_size || rva < s->mem_rva || rva - s->mem_rva >= span)
			continue;
		return s->file_off + (rva - s->mem_rva);
	}
	return 0;
}

/*
 * A DESTINATION THAT IS ALREADY WRITTEN IS NOT A DESTINATION.
 *
 * Without this the module runs on its own output: what it produces still
 * carries the table and every compressed stream - they are in the stub section
 * and nothing removes them - so the same table is found again and the same
 * blocks are laid over bytes that already hold them. Measured before this:
 * explorer.exe produced seven identical children and 111.exe twelve, until the
 * engine's depth limit stopped it.
 *
 * The test is the one that says what a packed destination IS: the bytes are
 * not there yet. Either the address resolves to no file bytes at all - the
 * hollow section in a file VMProtect wrote - or it resolves to zeroes, which
 * is what an image one layer in holds for the same section.
 *
 * SIXTEEN BYTES, and a block whose own output opens with sixteen zeroes would
 * be laid a second time. None of the nine blocks measured here does - they
 * open 0x40, 0x8b, 0xcd, 0xf2, 0x48, 0x55, 0x56, 0x42, 0x42 - and the cost of
 * being wrong is a repeat, not a wrong answer.
 */
#define VMP_EMPTY_LOOK 16u

static int vmp_dst_empty(const struct kof_obj_ctx *ctx,
			 const struct kof_pe_info *pe, uint32_t rva)
{
	uint64_t off = vmp_off_of(pe, rva);
	unsigned k;

	if (!off || !kof_in_obj(off, VMP_EMPTY_LOOK))
		return 1;
	for (k = 0; k < VMP_EMPTY_LOOK; k++)
		if (kof_u8(off + k))
			return 0;
	return 1;
}

/* The first byte of an LZMA stream is the range coder's, and it is zero. */
static int vmp_lzma_here(const struct kof_obj_ctx *ctx,
			 const struct kof_pe_info *pe, uint32_t rva)
{
	uint64_t at = vmp_off_of(pe, rva);

	if (!at || !kof_in_obj(at, 1u))
		return 0;
	return kof_u8(at) == 0u;
}

/*
 * The LZMA properties the file itself names, from the {RVA, 5} pair the stub
 * keeps in the slot before the table. A build that carries no such pair - the
 * 3.9+ layout - gets the encoder's defaults, which is what it uses.
 */
static uint32_t vmp_props_before(const struct kof_obj_ctx *ctx,
				 const struct kof_pe_info *pe, uint64_t at)
{
	uint64_t off;
	uint32_t b;

	if (at < 8u || !kof_in_obj(at - 8u, 8u))
		return VMP_PROPS_DEF;
	if (kof_u32(at - 4u) != VMP_PROPS_LEN)
		return VMP_PROPS_DEF;
	off = vmp_off_of(pe, kof_u32(at - 8u));
	if (!off || !kof_in_obj(off, VMP_PROPS_LEN))
		return VMP_PROPS_DEF;
	b = kof_u8(off);
	return b > VMP_PROPS_MAX ? VMP_PROPS_DEF : b;
}

/*
 * THE TABLE, FOUND BY THE THING THAT SITS IN FRONT OF IT.
 *
 * The section-shaped search below needs the packed sections' addresses, and it
 * gets them from the section table. That works on a file as VMProtect wrote
 * it and NOT on the same program one layer in: 111.exe is VMProtect under
 * MPRESS, and what MPRESS hands back is the IMAGE - every section present,
 * every byte of a hollow one there and zero. SizeOfRawData is no longer zero
 * for any of them, so "which sections are hollow" has no answer and the search
 * never started. That is the whole of why a VMProtect file reported VMProtect
 * and decrypted nothing.
 *
 * So the table is anchored on what is immediately in front of it instead: an
 * {RVA, 5} pair naming the five LZMA property bytes. Measured on both samples
 * to hand - 0x3d2464 in the file and 0x1cccc4-8 in the image - and it needs no
 * section table at all, because the entries that follow describe themselves:
 * each destination is page aligned, they ascend, and each source resolves to a
 * byte that is zero, which is what a raw LZMA stream opens with.
 */
static int vmp_find_by_props(const struct kof_obj_ctx *ctx,
			     const struct kof_pe_info *pe,
			     uint64_t image_end, struct vmp_tab *out)
{
	uint64_t at, end = ctx->obj_size;

	if (end < 24u)
		return 0;
	end -= 24u;

	for (at = 0; at <= end; at += 4u) {
		uint64_t po, e;
		uint32_t props, n = 0, last = 0;

		if (kof_u32(at + 4u) != VMP_PROPS_LEN)
			continue;
		po = vmp_off_of(pe, kof_u32(at));
		if (!po || !kof_in_obj(po, VMP_PROPS_LEN))
			continue;
		props = kof_u8(po);
		if (props > VMP_PROPS_MAX)
			continue;

		for (e = at + 8u; n < VMP_MAX_BLK && kof_in_obj(e, 8u);
		     e += 8u) {
			uint32_t src = kof_u32(e);
			uint32_t dst = kof_u32(e + 4u);
			uint64_t so;

			/* Ascending, page aligned, inside the image. */
			if (dst < PEI_PAGE || (dst & (PEI_PAGE - 1u)) ||
			    dst >= image_end || (n && dst <= last))
				break;
			so = vmp_off_of(pe, src);
			if (!so || !kof_in_obj(so, 1u) || kof_u8(so) != 0u)
				break;
			if (!vmp_dst_empty(ctx, pe, dst))
				break;
			out->src[n] = src;
			out->dst[n] = dst;
			last = dst;
			n++;
		}
		if (n >= VMP_MIN_BLK) {
			out->n = n;
			out->props = props;
			return 1;
		}
	}
	return 0;
}

/*
 * Walk the object for the table. `dst` holds the packed sections' addresses,
 * which is both what the entries must decrypt to and what the key is recovered
 * from.
 */
static int vmp_find_table(const struct kof_obj_ctx *ctx,
			  const struct kof_pe_info *pe,
			  const uint32_t *want, uint32_t n_want,
			  struct vmp_tab *out)
{
	uint64_t at, end;

	if (n_want < VMP_MIN_BLK || n_want > VMP_MAX_BLK)
		return 0;
	end = ctx->obj_size;
	if (end < (uint64_t)n_want * 8u)
		return 0;
	end -= (uint64_t)n_want * 8u;

	for (at = 0; at <= end; at++) {
		uint32_t k, seed, ok = 0;

		/* Cheapest first: entry zero's source has to look like a
		 * stream. Most offsets die here. */
		if (!kof_in_obj(at, (uint64_t)n_want * 8u))
			continue;
		if (!vmp_lzma_here(ctx, pe, kof_u32(at)))
			continue;
		for (k = 1; k < n_want; k++)
			if (!vmp_lzma_here(ctx, pe, kof_u32(at + k * 8u)))
				break;
		if (k != n_want)
			continue;

		for (seed = 0; seed < n_want; seed++) {
			uint32_t key = kof_u32(at + 4u) ^ want[seed];
			uint32_t seen = 0;

			for (k = 0; k < n_want; k++) {
				uint32_t d = kof_u32(at + k * 8u + 4u) ^
					     vmp_rol(key, 7u * k);
				uint32_t j;

				for (j = 0; j < n_want; j++)
					if (want[j] == d)
						break;
				if (j == n_want || (seen & (1u << j)))
					break;
				if (!vmp_dst_empty(ctx, pe, d))
					break;
				seen |= 1u << j;
				out->src[k] = kof_u32(at + k * 8u);
				out->dst[k] = d;
			}
			if (k == n_want) {
				out->n = n_want;
				out->props = vmp_props_before(ctx, pe, at);
				ok = 1;
				break;
			}
		}
		if (ok)
			return 1;
	}
	return 0;
}

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_pe_info *pe = kof_pe(ctx);
	uint32_t want[VMP_MAX_BLK], n_want = 0, i;
	struct vmp_tab tab;
	uint64_t image_end;
	uint32_t k;

	if (!pe->valid || pe->sec_count < 2u)
		return;

	image_end = pei_image_end(pe);

	/*
	 * TWO WAYS IN, AND THE ONE THAT NEEDS NOTHING IS TRIED FIRST.
	 *
	 * The {RVA, 5} anchor reads the table out of the object on its own
	 * terms. Only when there is none - the 3.9+ layout carries no props
	 * pair, because the loader has the properties built in - is the
	 * section-shaped search worth the walk, and that one needs the packed
	 * sections' addresses, so it is gated on there being some.
	 */
	if (vmp_find_by_props(ctx, pe, image_end, &tab)) {
		/*
		 * THE LAYOUT IS THE VERSION, and this module already branched
		 * on it before it could say so. A props pair in the table is
		 * what the builds up to 3.8 write; 3.9 moved the properties
		 * into the loader and stopped writing them, which is why the
		 * search below exists at all.
		 *
		 * So the branch names itself - see `packer_build` in kofsig.h.
		 * A range rather than a point because that is what the evidence
		 * supports: the presence of the pair separates the two eras and
		 * says nothing finer.
		 */
		kunp_rcstruct_build("PE:VMProtect <= 3.8");
	} else {
		/*
		 * NOT YET A CLAIM. Having no props pair is what 3.9 looks like
		 * and also what every PE that is not VMProtect looks like, so
		 * the name waits until the search below has found blocks. The
		 * engine drops a build from a module that opens nothing, but a
		 * module should not be making the claim in the first place.
		 */
		/* The hollow sections that are not BSS. */
		for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
			const struct kof_pe_sec *s = &pe->sec[i];

			if (s->file_size || s->file_off || !s->mem_size)
				continue;
			if (s->characteristics & 0x00000080u)  /* UNINIT */
				continue;
			if (n_want < VMP_MAX_BLK)
				want[n_want++] = (uint32_t)s->mem_rva;
		}
		if (n_want)
			kunp_rcstruct_build("PE:VMProtect 3.9+");
		if (n_want < VMP_MIN_BLK)
			return;                          /* not this shape */
		if (!vmp_find_table(ctx, pe, want, n_want, &tab))
			KUNP_RCSTRUCT_BROKEN(KOF_UNP_UNSUPPORTED);
	}

	kof_debug("VMProtect.PE.blocks", tab.n);

	/*
	 * ---- THE LAYOUT, DECLARED --------------------------------------------
	 *
	 * The parent's sections at their own addresses, with two things the old
	 * shape could not say and which cost this module real ground:
	 *
	 *   HOLLOW survives. The destinations are recognised by having no bytes
	 *   behind them, and a synthesised header had to claim the span or the
	 *   child would not read back - so one layer in they stopped looking
	 *   hollow and this module found nothing at all in 111.exe.
	 *
	 *   The permission is CORRECTED once a block has been laid, below.
	 *   The layer above drew these regions while they were still zeroes, so
	 *   102400 bytes of `55 8b ec` were filed under DATA until a poke into
	 *   a header put it right.
	 */
	/*
	 * ---- THE LAYOUT FIRST, BECAUSE THE ENGINE SIZES THE IMAGE FROM IT ----
	 *
	 * Addresses and extents only. What each section IS is not said here and
	 * must not be: at this point nothing has been decompressed, so any
	 * answer would describe the PARENT - and that is exactly the mistake
	 * that was measured. Declaring the destinations hollow from the
	 * parent's shape left them reading as empty in a child that had just
	 * been filled, so this module accepted its own output and
	 * explorer.exe came back as seven identical objects.
	 *
	 * The truth is said further down, after the content exists and has been
	 * read back. A region is unique by its address, so saying it again
	 * replaces it.
	 */
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];

		if (kunp_rcstruct_section(s->name, s->mem_rva, pei_span(s),
				    s->perm, KOF_SECF_DATA | KOF_SECF_READ) < 0)
			KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	}
	if (!kunp_rcstruct_image())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);
	kunp_rcstruct_entry(pe->entry_rva);

	/* What the parent already holds, where it holds it. */
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];
		uint64_t span = pei_span(s), have = s->file_size;

		if (!have)
			continue;
		if (have > span)
			have = span;
		if (!kunp_rcstruct_at(s->mem_rva))
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
		if (!pei_copy(ctx, s->file_off, have))
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
	}

	/*
	 * AND THE BLOCKS, DECOMPRESSED STRAIGHT TO WHERE THEY BELONG.
	 *
	 * Addresses, not stream positions: the four destinations on 111.exe are
	 * 0x1000, 0x1a000, 0x1d000 and 0x1e000, and only the first is at a
	 * section start. The cursor is what makes that a statement rather than
	 * a walk with a pad on either side of it.
	 */
	for (k = 0; k < tab.n; k++) {
		uint64_t src = vmp_off_of(pe, tab.src[k]);
		uint64_t room = image_end > tab.dst[k]
			      ? image_end - tab.dst[k] : 0;
		uint64_t wrote;

		if (!src || !room)
			continue;
		if (!kunp_rcstruct_at(tab.dst[k]))
			kunp_rcstruct_broken(KOF_UNP_LIMIT);
		wrote = kunp_static_decode(KOF_UNP_LZMA + tab.props, src,
					   ctx->obj_size - src, room);
		if (!wrote)
			KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	}

	/*
	 * ---- AND NOW WHAT IS ACTUALLY THERE ---------------------------------
	 *
	 * Read back, one section at a time, and said again. This is the only
	 * point at which the answer is about the child rather than about the
	 * thing it came from.
	 *
	 *   filled + opens with a prologue -> code, and REBUILT;
	 *   filled at all                  -> data, and REBUILT;
	 *   never filled and never had any -> HOLLOW, and READ;
	 *   otherwise                      -> as the parent had it.
	 *
	 * The code test stays narrow and only ever ADDS execute: the 1.5 MB
	 * block at 0x1e000 measures 7.52 bits per byte and is the virtualised
	 * layer, which is not code this engine can read and must not be called
	 * any.
	 */
	for (i = 0; i < pe->sec_count && i < KOF_PE_MAX_SECTIONS; i++) {
		const struct kof_pe_sec *s = &pe->sec[i];
		uint32_t f, perm = s->perm;
		uint8_t h[4];
		int filled = 0;

		for (k = 0; k < tab.n; k++)
			if (tab.dst[k] >= s->mem_rva &&
			    tab.dst[k] - s->mem_rva < pei_span(s)) {
				filled = 1;
				break;
			}
		if (filled) {
			f = KOF_SECF_DATA | KOF_SECF_REBUILT;
			if (kunp_rcstruct_read(s->mem_rva, h, 4u) == 4u &&
			    ((h[0] == 0x55u && h[1] == 0x8bu && h[2] == 0xecu) ||
			     (h[0] == 0x55u && h[1] == 0x89u && h[2] == 0xe5u) ||
			     (h[0] == 0x48u && h[1] == 0x89u && h[2] == 0x5cu) ||
			     (h[0] == 0x48u && h[1] == 0x83u && h[2] == 0xecu) ||
			     (h[0] == 0x40u && h[1] == 0x53u))) {
				f = KOF_SECF_CODE | KOF_SECF_REBUILT;
				perm |= KOF_PE_PERM_X;
			}
		} else if (!s->file_size && !s->file_off) {
			f = KOF_SECF_DATA | KOF_SECF_HOLLOW | KOF_SECF_READ;
		} else {
			f = ((s->perm & KOF_PE_PERM_X) ? KOF_SECF_CODE
						       : KOF_SECF_DATA) |
			    KOF_SECF_READ;
		}
		if (kunp_rcstruct_section(s->name, s->mem_rva, pei_span(s),
				    perm, f) < 0)
			KUNP_RCSTRUCT_BROKEN(KOF_UNP_DAMAGED);
	}

	if (!kunp_rcstruct_done())
		kunp_rcstruct_broken(KOF_UNP_LIMIT);

	/*
	 * AND NOT ENCRYPTED, WHICH IS WHAT THIS USED TO SAY.
	 *
	 * Whatever was virtualised inside the program is still virtualised -
	 * that is true, and it is a fact about the CHILD. `kunp_rcstruct_broken`
	 * marks the object the module was WORKING ON, so saying it here put
	 * "not finished: Encrypted content" on the parent: on 111.exe that is
	 * the MPRESS image, whose every VMProtect block this module had just
	 * read out in full. Nothing about that object was left undone, and a
	 * reader was told it was.
	 */
}
