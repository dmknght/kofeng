/*
 * tar.c - open a tar, one child per entry, for nothing.
 *
 * The cheapest unpacker in the database, and the only one that spends no budget at
 * all: a tar stores its entries uncompressed, so every child is a WINDOW - the
 * parent's own mapping seen through an offset. No copy, no memory, no decoder.
 *
 * Which makes what it completes worth more than what it costs. Almost nothing
 * arrives as a plain tar; it arrives as a tar inside a gzip, and the engine already
 * pays the expensive part of that - measured over this collection, 268 of 295 gzip
 * files hold one. Before this module the inflate ran, produced the tar as a child,
 * and the child identified as nothing.
 *
 * Directories and the GNU pseudo entries are skipped because there is nothing in
 * them: a directory has no content, and a long-name entry's content is the NEXT
 * entry's name, which the parse already resolved into that entry's name_off. Making
 * children of either would spend the child budget on objects that are not files.
 */

#include <kofmod/kofsig.h>
#include <kofmod/tar.h>

KOF_UNPACK_KIND(KOF_UNP_CONTAINER);

KOF_TARGET_FORMAT(KOF_FMT_TAR);

void kof_unpack(const struct kof_obj_ctx *ctx)
{
	const struct kof_tar_info *t = kof_tar(ctx);
	uint32_t i, opened = 0;

	if (!t->valid)
		return;

	kof_debug("Tar.entries", t->n_entries);
	kof_debug("Tar.files", t->n_files);

	for (i = 0; i < t->n_entries; i++) {
		const struct kof_tar_entry *e = &t->entry[i];

		if (!e->size)
			continue;               /* a directory, or an empty file */
		switch (e->typeflag) {
		case KOF_TAR_T_FILE:
		case KOF_TAR_T_FILE_ALT:
			break;
		default:
			continue;               /* not content: a link, a pseudo entry */
		}
		/*
		 * Content the object does not actually hold. The parse recorded it;
		 * this only has to not ask for a window onto bytes that are not there,
		 * which the host would refuse anyway.
		 */
		if (e->suspicious & KOF_TAR_ENT_PAST_EOF)
			continue;

		/* What this entry is called, for the report. */
		kof_name_next(e->name_off, e->name_len);

		if (!kof_child_window(e->data_off, e->size))
			break;                  /* a host limit bound: stop, do not spin */
		opened++;
	}

	kof_debug("Tar.opened", opened);

	/*
	 * Entries the archive declares and this object does not contain.
	 *
	 * Said with DAMAGED rather than LIMIT because nothing here reached a limit:
	 * the archive was cut, or its sizes do not describe it. A truncated tar is
	 * still worth every entry that survived, which is why this reports rather
	 * than refuses.
	 */
	if (t->anomalies & (KOF_TAR_ANOM_TRUNCATED | KOF_TAR_ANOM_BAD_SIZE))
		kof_unp_broken(KOF_UNP_DAMAGED);
	if (t->anomalies & KOF_TAR_ANOM_ENTRIES_FULL)
		kof_unp_broken(KOF_UNP_LIMIT);
}
