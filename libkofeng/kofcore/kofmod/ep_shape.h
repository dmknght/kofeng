/*
 * ep_shape.h - "the entry point begins with THESE bytes, give or take these".
 *
 * A table of entry-point patterns is how every tool that names packers does it,
 * and three modules here need the same three things from one: wildcards, a
 * bound that keeps the read inside the object, and a version string attached to
 * the row that matched. Written three times it would be written three ways.
 *
 *
 * WHY A WILDCARD AND NOT A PREFIX. A stub's first instructions are the same in
 * every file of a build except for the ADDRESSES in them - `mov eax, imm32`
 * where imm32 is this file's own image base, `lea reg, [eax + disp32]` where
 * disp32 is where the builder put the loader. A prefix that stops before the
 * first immediate throws away everything after it, and everything after it is
 * what tells one build from the next. So the immediates are holes.
 *
 *
 * WHAT A MATCH IS AND IS NOT. It is NECESSARY and never sufficient. These bytes
 * are public - XVolkolak carries ASPack's 2.12 signature a second time under
 * the name FAKESIGNATURE, because other packers stamp it at their own entry
 * points so that tools report ASPack and stop looking. Every caller here pairs
 * a row with a second, structural fact that a forgery does not carry: a section
 * the packer must have written, a table at a fixed distance, a header the
 * builder rewrote.
 */

#ifndef KOF_EP_SHAPE_H
#define KOF_EP_SHAPE_H

#define EPS_MAX 32u     /* bytes in a row; the mask is one bit each */

/*
 * `n` bytes of `b`, with a 1 bit in `wild` for each position that may be
 * anything. Rows are tried in order, so a longer row that a shorter one is a
 * prefix of has to come first - the caller's table is the priority.
 */
struct eps_row {
	uint8_t  b[EPS_MAX];
	uint32_t wild;
	uint8_t  n;
	char     name[28];
};

/*
 * The first row matching at `at`, or -1.
 *
 * Reads through kof_u8 a byte at a time and bails on the first that is out of
 * the object, so a file that ends inside the pattern matches nothing rather
 * than matching what happens to be mapped after it.
 */
static int eps_match(const struct kof_obj_ctx *ctx, uint64_t at,
		     const struct eps_row *rows, uint32_t n_rows)
{
	uint32_t r, k;

	for (r = 0; r < n_rows; r++) {
		const struct eps_row *row = &rows[r];

		if (row->n > EPS_MAX)
			continue;
		for (k = 0; k < row->n; k++) {
			if (row->wild & (1u << k))
				continue;
			if (!kof_in_obj(at + k, 1u) ||
			    kof_u8(at + k) != row->b[k])
				break;
		}
		if (k == row->n)
			return (int)r;
	}
	return -1;
}

#endif /* KOF_EP_SHAPE_H */
