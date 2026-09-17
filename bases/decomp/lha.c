/*
 * lha.c - the compressed files in an LHA archive.
 *
 * WHY A MODULE FOR THIS, when a stored entry needs none. The host opens a
 * carried file generically when the entry is a RANGE - see kof_objtree_declared
 * - and deliberately does not when the entry declares a coding, because the
 * bytes at that range are not the file. Decoding is a copy and a budget, which
 * is a different operation from pointing at bytes that already exist.
 *
 * So a "-lh0-" entry arrives as a child with nothing written here, and this
 * file exists for "-lh5-", "-lh6-" and "-lh7-" - one coding under three
 * dictionary sizes, see KOF_UNP_LZHUF_LH5.
 *
 * WHAT IS NOT OPENED: "-lh1-" through "-lh4-" and "-lzs-", which are older and
 * different codings this build has no decoder for. The parse counts them in
 * n_coded and none is reported as engine failure - a gap a later build closes
 * is not damage in the file.
 */

#include <kofmod/kofsig.h>
#include <kofmod/lha.h>

KOF_TARGET_FORMAT(KOF_FMT_LHA);
/*
 * A CONTAINER, not a packer: an archive carries files that were separately
 * there. Depth through it is a directory tree rather than a layer of packing,
 * and a heuristic that weighs "this was packed" must not weigh this.
 */
KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_lha_info *l = kof_lha(ctx);
	uint32_t i, opened = 0;

	if (!l->valid)
		return;

	for (i = 0; i < l->n_entries; i++) {
		const struct kof_entry *e = &l->entry[i];

		/* The stored ones are the host's - opening them here would
		 * produce every one of them twice. */
		if (!e->coding[0])
			continue;
		/* The name the entry already carries, so the child is called
		 * what the archive calls it rather than a number. */
		kof_name_next(e->name_off, e->name_len);
		/*
		 * out_hint is the original size, and for this coding it is
		 * what ENDS the stream rather than a guess at its output -
		 * see KOF_UNP_LZHUF_LH5.
		 */
		if (!kof_unpack_at(e->coding[0], e->off, e->len, e->out_hint))
			continue;
		if (!kof_child())
			break;
		opened++;
	}

	kof_debug("Lha.decoded", opened);
	/* Everything the archive holds behind a coding, including what was
	 * opened above: a reader asking "how much of this is compressed" means
	 * that, not "how much was left". */
	kof_debug("Lha.coded", l->n_coded);
}
