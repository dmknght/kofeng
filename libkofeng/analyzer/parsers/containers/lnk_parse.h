/*
 * lnk_parse.h - read a Windows shell link. See kofmod/lnk.h for the format and
 * for why a shortcut is worth parsing at all.
 */

#ifndef KOFENG_LNK_PARSE_H
#define KOFENG_LNK_PARSE_H

#include <kofmod/lnk.h>
#include <kofmod/kofsig.h>

#include "../../../kofcore/kofcore.h"

int kof_lnk_parse(kof_buf file, struct kof_lnk_info *info,
		  struct kof_obj_ctx *ctx);
int kof_lnk_sniff(kof_buf file);

const char *kof_lnk_region_name(uint32_t bit);
const char *kof_lnk_anomaly_name(unsigned index);

/*
 * In file order rather than in bit order: LINKINFO's four pieces are listed
 * where they occur, which is inside it, and EXTRA's three the same. See the
 * note on KOF_SCAN_LNK_UNCLAIMED in kofmod/lnk.h for why the bits themselves
 * were not renumbered to match.
 */
#define LNK_REGIONS(X)            \
	X(KOF_SCAN_LNK_HEADER)    \
	X(KOF_SCAN_LNK_IDLIST)    \
	X(KOF_SCAN_LNK_LINKINFO)  \
	X(KOF_SCAN_LNK_VOLUMEID)  \
	X(KOF_SCAN_LNK_LOCALPATH) \
	X(KOF_SCAN_LNK_NETPATH)   \
	X(KOF_SCAN_LNK_NAME)      \
	X(KOF_SCAN_LNK_RELPATH)   \
	X(KOF_SCAN_LNK_WORKDIR)   \
	X(KOF_SCAN_LNK_ARGUMENTS) \
	X(KOF_SCAN_LNK_ICON)      \
	X(KOF_SCAN_LNK_EXTRA)     \
	X(KOF_SCAN_LNK_ENVTARGET) \
	X(KOF_SCAN_LNK_ICONENV)   \
	X(KOF_SCAN_LNK_TRACKER)   \
	X(KOF_SCAN_LNK_UNCLAIMED)

extern const uint32_t kof_lnk_region_bits[];
#define KOF_LNK_REGION_COUNT 16u  /* asserted against the array in the .c */

#endif /* KOFENG_LNK_PARSE_H */
