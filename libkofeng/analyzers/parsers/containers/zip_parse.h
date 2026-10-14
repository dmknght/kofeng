/*
 * zip_parse.h - the zip collector, for both formats that share the view.
 *
 * Same shape as every other collector: a sniff that needs no view buffer, a parse
 * that fills both the common context and the format view, and a parse that never
 * fails - hostile or truncated input yields what was recovered plus anomaly bits.
 *
 * The structure only. Nothing here inflates an entry: that costs budget and is an
 * unpacker's business, reached through the host. What this produces for free is
 * every entry's name, where its bytes are, and whether they can be searched where
 * they lie - which on a document is most of the answer.
 */

#ifndef KOFENG_ZIP_PARSE_H
#define KOFENG_ZIP_PARSE_H

#include <kofmod/zip.h>
#include <kofmod/kofsig.h>
#include "../../../kofcore/kofcore.h"

/*
 * Returns non-zero if the object is a zip.
 *
 * On a non-zero return ctx->file_header points at info and ctx->format is
 * KOF_FMT_ZIP or KOF_FMT_DOCZIP - the parse decides which from the entry names,
 * which is why the caller cannot know it in advance and must not assume it.
 */
int kof_zip_parse(kof_buf file, struct kof_zip_info *info,
		  struct kof_obj_ctx *ctx);

/*
 * THE VIEW'S TABLES ARE THE FILE'S SIZE, so a view owns memory.
 *
 * `info->mem.room` is set by the caller before the parse: the bytes the tables may hold
 * (the engine passes what its per-object ledger has left; a test or a tool passes what it
 * is willing to spend). The parse clears the view, and a view must therefore start zeroed
 * - what an earlier parse left in it is let go first, so a zeroed view and a used one are
 * the same to it. After the parse `info->mem.held` is what the tables hold, for the
 * caller to charge, and kof_zip_release gives it all back: the view is then empty and
 * parses again. A table that cannot grow is not a failed parse - the rows read so far are
 * whole and KOF_ZIP_ANOM_ENTRIES_FULL / _EXTENTS_FULL say the rest was not.
 */
void kof_zip_release(struct kof_zip_info *info);

/* The host's three handles on a view that has tables - see struct kof_view_ops in
 * kofformat.h: its account, its release, and the walk a module's kof_zip_next reaches. */
struct kof_view_mem *kof_zip_mem(void *view);
const void *kof_zip_row(void *view, uint32_t *cursor);

/*
 * Does this object look like a zip?
 *
 * A local header or an end record at offset zero, and nothing else. In particular
 * this does NOT search the tail for an end record, which would find the zip inside
 * every self-extracting archive - and finding it here would be the wrong place. An
 * SFX is an executable that happens to carry an archive: it should be identified as
 * the executable it is, parsed as one, and the archive reached as its overlay. One
 * object, one format, and the layering does the rest.
 */
int kof_zip_sniff(kof_buf file);

const char *kof_zip_region_name(uint32_t bit);
const char *kof_zip_anomaly_name(unsigned index);
const char *kof_zip_kind_name(uint32_t kind);

/* THE REGION LIST, where everything that needs it can see it.
 * It lived in the .c, so ksigbuilder - which has to turn the name a
 * signature writes back into a bit - kept a hand copy in rgn_names[]
 * with, in its own words, no build-time check that it had not fallen
 * behind. Now there is one list and one place to add to. */
#define ZIP_REGIONS(X)            \
	X(KOF_SCAN_ZIP_HEADERS)     \
	X(KOF_SCAN_ZIP_NAMES)       \
	X(KOF_SCAN_ZIP_STORED)      \
	X(KOF_SCAN_ZIP_PACKED)      \
	X(KOF_SCAN_ZIP_UNCLAIMED)

extern const uint32_t kof_zip_region_bits[];
#define KOF_ZIP_REGION_COUNT 5u   /* asserted against the array in the .c */

#endif /* KOFENG_ZIP_PARSE_H */
