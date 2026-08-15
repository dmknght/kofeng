/*
 * xz.c - decode an xz stream's blocks.
 *
 * The cheapest container to add that this engine has had. Its coder is LZMA2,
 * which was written to reach 7z content and is already here and already checked
 * against a reference on 256 real streams - so this module is the twelve lines
 * that point it at a block.
 *
 * One child per block rather than one for the stream: blocks are independently
 * coded and a stream is split into them precisely so they can be handled apart,
 * so joining them here would undo the only structure the format has.
 */

#include <kofmod/kofsig.h>
#include <kofmod/xz.h>

KOF_TARGET_FORMAT(KOF_FMT_XZ);

KOF_DEFINE_UNPACK
{
	const struct kof_xz_info *x = kof_xz(ctx);
	uint32_t i, opened = 0, unreached = 0;

	if (!x->valid)
		return;

	kof_debug("Xz.check", x->check);
	kof_debug("Xz.blocks", x->n_blocks);

	for (i = 0; i < x->n_blocks; i++) {
		const struct kof_xz_block *b = &x->block[i];

		if (!b->comp_size || (b->suspicious & KOF_XZ_BLK_PAST_EOF))
			continue;
		/*
		 * A filter in front of the coder is recorded and not run. Decoding
		 * only the coder half of a chain produces bytes that are not the
		 * file - the transform was applied to them on the way in and has to
		 * be undone on the way out - so the honest answer is to say the
		 * block was not read.
		 */
		if ((b->suspicious & KOF_XZ_BLK_CHAIN) ||
		    b->filter != KOF_XZ_FILTER_LZMA2) {
			unreached++;
			continue;
		}
		if (kof_unpack_at(KOF_UNP_LZMA2, b->data_off, b->comp_size,
				  b->uncomp_size) == 0) {
			unreached++;
			continue;
		}
		if (!kof_child())
			KOF_UNP_BROKEN(KOF_UNP_LIMIT);
		opened++;
	}

	kof_debug("Xz.opened", opened);

	if (unreached)
		kof_unp_broken(KOF_UNP_UNSUPPORTED);
	if (x->anomalies & (KOF_XZ_ANOM_TRUNCATED | KOF_XZ_ANOM_BAD_BLOCK |
			    KOF_XZ_ANOM_NO_INDEX | KOF_XZ_ANOM_BAD_FOOTER))
		kof_unp_broken(KOF_UNP_DAMAGED);
	if (x->anomalies & (KOF_XZ_ANOM_BLOCKS_FULL | KOF_XZ_ANOM_EXTENTS_FULL))
		kof_unp_broken(KOF_UNP_LIMIT);
	if (!x->n_blocks)
		kof_unp_broken(KOF_UNP_DAMAGED);
}
