/*
 * kofread.h - reading the object under scan: scalars, the symbol and graph
 * records, cross references, bounds checks, and measuring a region.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFREAD_H
#define KOFENG_KOFREAD_H

#include <stdint.h>
#include "kofctx.h"
#include "kofregion.h"

/*
 * READING SCALARS OUT OF THE OBJECT
 *
 *     if (kof_u16(0) == 0x5a4d) ...
 *     uint32_t rva = kof_u32(ep + 1);
 *
 * The byte accessors, spelled the way they are used. Reaching through the vtable by
 * hand - ctx->content->rd32(ctx, off) - names the context twice and the mechanism
 * once, for a read that is the most ordinary thing a module does.
 *
 * Little endian, and that is a statement about the accessors rather than about
 * every structure a module reads. A big endian ELF's own headers arrive through the
 * parsed view with the byte order already dealt with - but a PACKER'S structures do
 * not: UPX writes its l_info and b_info in the target's byte order, into a file the
 * collector has no reason to normalise, so a module reading them on a big endian
 * object has to swap. kof_bswap* below is for exactly that, and it needs no second
 * set of accessors: these hand over the bytes and the module says what they mean.
 *
 * An out of range read yields zero rather than faulting, so a module that must tell
 * "the bytes there are zero" from "there are no bytes there" asks first:
 *
 *     if (kof_in_obj(off, 4) && kof_u32(off) == 0) ...
 */
/*
 * Byte order, for the structures the accessors above cannot know about.
 *
 * A module that reads a packer's own header on a big endian object needs these; one
 * that reads a format's header does not, because the collector normalised that
 * already. Written out rather than taken from a system header, because a signature
 * module has no libc and cannot include one.
 */
static inline uint16_t kof_bswap16(uint16_t v)
{
	return (uint16_t)((v >> 8) | (v << 8));
}

static inline uint32_t kof_bswap32(uint32_t v)
{
	return ((v & 0xff000000u) >> 24) | ((v & 0x00ff0000u) >> 8) |
	       ((v & 0x0000ff00u) << 8)  | ((v & 0x000000ffu) << 24);
}

/*
 * The object's symbol records, and how many bytes of them.
 *
 * Named like the other content accessors so a rule reads the same way:
 *
 *     uint32_t n; const uint8_t *b = kof_syms(&n), *r;
 *     for (i = 0; (r = kof_sym_rec(b, n, i)); i++)
 *             if (r[KOF_SYM_R_TYPE] == 1 && r[KOF_SYM_R_BIND] == 1)
 *                     ... kof_sym_name(b, n, r, &len) ...      its whole name
 *
 * NULL and zero for an object with no symbols - a stripped file, or any
 * non-ELF - which is a normal answer and stops the loop on its first test.
 */
#define kof_syms(np) ((ctx)->content->syms ? \
		      (ctx)->content->syms((ctx), (np)) : 0)

/*
 * The diagnose graph's records, and how many bytes of them - see
 * kofmod/kofdiagtree.h for the layout and for why this is a block rather than
 * the engine's own struct.
 *
 *     uint32_t n; const uint8_t *g = kof_diag_graph(&n), *r;
 *     for (i = 0; (r = kof_gr_rec(g, n, i)); i++)
 *             if (kof_gr_u16(r, KOF_GR_R_CAP) == KOF_NUCLEO_ACTION_WRITE)
 *                     ...
 *
 * NULL and zero when the analysis did not run on this object, which is a
 * normal answer and stops the loop on its first test. Reading this cannot
 * make it run: the analysis runs when a diagnose that declares a disease can be
 * answered on the object, or when a module asks kof_diag.
 */
#define kof_diag_graph(np) ((ctx)->content->graph ? \
			    (ctx)->content->graph((ctx), (np)) : 0)

/*
 * WHICH CODE REFERS TO THE DATA AT `va`, AND HOW.
 *
 *     if (kof_data_xref(sym_value, sym_size) & (KOF_XREF_CALL | KOF_XREF_JUMP))
 *             ...this variable is executed, whatever its bytes look like
 *
 * The question a rule looking for a payload actually wants answered. Asking
 * what the BYTES look like - how unprintable they are, whether a syscall
 * instruction is in them - is defeated by encoding the payload, which is the
 * first thing anyone does to it. An ordinary variable is read; a payload is
 * executed; and that difference is in the code, where no encoding of the data
 * reaches.
 *
 * FIVE MECHANICAL FACTS AND NO CONCLUSIONS. The engine says what the
 * instructions did; what that MEANS is composed in bases/, next to the rest of
 * the vocabulary of malware. A rule looking for a payload staged into a fresh
 * mapping wants KOF_XREF_ARG, one looking for a direct call wants
 * KOF_XREF_CALL, and neither needs a line changed here.
 *
 * A RANGE, because a blob is not referred to at its first byte - see
 * kof_xref_in in libgenome/celllysis/xref.h for the three-load measurement that says so.
 * Pass the variable's own size; 0 asks about the one address.
 *
 * Zero for a range nothing referred to, and zero for an object with no code to
 * sweep. NOT an assertion that the variable is unused: see KOF_XREF_PARTIAL.
 */
#define kof_data_xref(va, size) ((ctx)->content->data_xref ?               \
				 (ctx)->content->data_xref((ctx),           \
							   (uint64_t)(va),  \
							   (uint64_t)(size)) : 0u)

/* KOF_XREF_*: the flags of kof_data_xref - defined by libgenome with the sweep
 * that computes them (<celllysis/xref.h>), included at the top of this file. */

#define kof_u8(off)  ((ctx)->content->rd8 ((ctx), (uint64_t)(off)))
#define kof_u16(off) ((ctx)->content->rd16((ctx), (uint64_t)(off)))
#define kof_u32(off) ((ctx)->content->rd32((ctx), (uint64_t)(off)))
#define kof_u64(off) ((ctx)->content->rd64((ctx), (uint64_t)(off)))

/*
 * Are n bytes at off inside the object?
 *
 * Written as "n <= size - off" after establishing "off <= size", so no addition
 * happens and nothing can wrap - both arguments may be values the file chose.
 *
 * A function under the macro rather than the comparison inline, because a module
 * asking about a constant offset - kof_in_obj(0, 4), which is how a magic check
 * reads - would otherwise trip -Wtype-limits on "0 <= unsigned". The signature
 * build treats warnings as errors, so that would make the natural spelling
 * unwritable.
 */
static inline int kof_range_in_obj(uint64_t obj_size, uint64_t off, uint64_t n)
{
	return off <= obj_size && n <= obj_size - off;
}

#define kof_in_obj(off, n)                                                 \
	kof_range_in_obj((ctx)->obj_size, (uint64_t)(off), (uint64_t)(n))

/* Compare bytes the module built at run time. kof_find_str_at is the one to reach
 * for when the bytes are a declared pattern; this is for bytes that are not. */
#define kof_memeq(off, p, n)                                               \
	((ctx)->content->memeq((ctx), (uint64_t)(off), (p), (uint32_t)(n)))

#define kof_csum(off, n)                                                   \
	((ctx)->content->csum((ctx), (uint64_t)(off), (uint32_t)(n)))

/*
 * Measure a region instead of reading it.
 *
 *     struct kof_region_shape u;
 *     if (kof_region_shape(KOF_SCAN_ELF_UNCLAIMED, &u) && u.widest >= 4096)
 *             ...  u.widest_off is where the run starts
 *
 * Non-zero when *out was filled. See `region_shape` in struct kof_content.
 */
#define kof_region_shape(mask, out)                                        \
	((ctx)->content->region_shape ?                                    \
	 (ctx)->content->region_shape((ctx), (uint32_t)(mask), (out)) : 0)

/*
 * How random that region's bytes are, in eighths of a bit - 0 to 64.
 *
 *     if (kof_region_entropy(KOF_SCAN_ELF_UNCLAIMED) >= 8u * 7u) ...
 *
 * Eighths and not a fraction: a module has no floating point. See
 * `region_entropy` in struct kof_content.
 */
#define kof_region_entropy(mask)                                           \
	((ctx)->content->region_entropy ?                                  \
	 (ctx)->content->region_entropy((ctx), (uint32_t)(mask)) : 0u)

/*
 * How random the bytes at [off, off+len) are, in eighths of a bit.
 *
 *     if (kof_entropy_at(u.widest_off, u.widest) >= 8u * 2u) ...
 *
 * The extent form, for a caller that has one run rather than a region - see
 * `entropy_at` in struct kof_content for why the two are not the same question.
 */
#define kof_entropy_at(off, len)                                           \
	((ctx)->content->entropy_at ?                                      \
	 (ctx)->content->entropy_at((ctx), (uint64_t)(off),                \
				    (uint64_t)(len)) : 0u)

#endif /* KOFENG_KOFREAD_H */
