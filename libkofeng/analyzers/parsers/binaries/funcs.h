#ifndef KOFENG_BINARIES_FUNCS_H
#define KOFENG_BINARIES_FUNCS_H

/*
 * funcs.h - the functions an object's symbols name, as file extents.
 *
 * A PRODUCT BESIDE THE SYMBOL BLOCK, built by the same step for the same reason:
 * which format's table feeds it is one decision (sym_any.c), made once, and
 * every consumer reads the result. The diagnose routes, the similarity carve
 * and anything after them used to each walk the symbol table for the functions
 * themselves - three loops growing an array of (address, size), three places
 * for the cap, the zero-size rule and the alias rule to differ.
 *
 * IT IS NOT THE SYMBOL BLOCK, and cannot be read out of it: the block is capped
 * at KOF_SYM_MAX_RECS records as a cost bound, and 24 of 272 measured objects
 * hold more symbols than that - the large static binaries, which are exactly
 * the ones with the most functions. This is built from the table itself, in
 * the file's own coordinates, with no cap but the table's own length.
 *
 * ELF: THE FUNCTIONS OF THE SYM_EXP REGION - the defined symbols the symbol block
 * already separates from the undefined ones. PE: the RUNTIME_FUNCTION table of an
 * x64 image (.pdata), which is the only place a PE states where a function ends
 * - exports carry no size - with the chained fragments left out. A 32-bit PE has
 * no such table, so it has no functions, like a stripped ELF. There is one list:
 * a consumer that wants fewer filters it, the list does not carry a second
 * opinion about which of its entries count.
 *
 * `off` is a FILE offset. A function the segments cannot place, a symbol with no
 * size (it names a place, not a body), and a label inside another body are not
 * listed; two names for one address are one function and the longer extent
 * stands. Sorted by offset. An object with no symbols is an empty set, which is
 * the answer: the functions of a stripped file are not known.
 */

#include <stdint.h>

struct kof_func {
	uint64_t off, len;
	/* The symbol this function is, as the symbol block records it - its value and
	 * section - so a tool shows the name from the block and not from here. Zero
	 * for a function with no symbol (PE: .pdata names nothing). */
	uint64_t value;
	uint16_t shndx;
};

struct kof_func_set {
	struct kof_func *v;     /* malloc'd; NULL when n is zero */
	uint32_t n;
	int oom;                /* short for want of memory, not for want of functions */
};

/* The one decision about which format's symbols feed it - see kof_syms_build. */
void kof_funcs_build(uint32_t format, const uint8_t *data, uint64_t data_n,
		     const void *info, struct kof_func_set *out);

void kof_funcs_free(struct kof_func_set *s);

/*
 * THE FUNCTIONS OF A VIEW, from the object it is a view of.
 *
 * A normalised view is its parent with padding collapsed and the static
 * library moved to the tail, so its headers cannot name the functions - and
 * the functions themselves are untouched: measured over 40 Mirai samples,
 * 5067 of 5076 unit extents (99.82%) are byte-identical in the view, and the
 * nine that are not each hold a zero run the collapse shortened. So each
 * function of the parent is looked for, as bytes, in the view - forward from
 * where the last one was found, since the view keeps the order, and only a
 * little way (the library was cut out, not shuffled). A function not found
 * there is not in the set: the library's, or one the collapse rewrote.
 * Offsets are the view's. `value` and `shndx` come along so a tool still
 * names it.
 */
void kof_funcs_remap(const uint8_t *par, uint64_t par_n,
		     const struct kof_func_set *pf, const uint8_t *view,
		     uint64_t view_n, struct kof_func_set *out);

/*
 * The last step of every format's builder, once: sort by offset, keep one
 * function per address (the longer extent stands) and no label inside another
 * body. Takes the malloc'd array `v` of `n` entries into `out`; frees it when
 * nothing is left.
 */
void kof_funcs_finish(struct kof_func *v, uint32_t n, struct kof_func_set *out);


#endif /* KOFENG_BINARIES_FUNCS_H */
