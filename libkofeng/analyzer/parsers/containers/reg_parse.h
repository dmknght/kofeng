/*
 * reg_parse.h - read a registry script. See kofmod/reg.h for the format and
 * for why a text file is worth splitting into regions.
 */

#ifndef KOFENG_REG_PARSE_H
#define KOFENG_REG_PARSE_H

#include <kofmod/reg.h>
#include <kofmod/kofsig.h>

#include "../../core/kofcore.h"

int kof_reg_parse(kof_buf file, struct kof_reg_info *info,
		  struct kof_obj_ctx *ctx);
int kof_reg_sniff(kof_buf file);

const char *kof_reg_region_name(uint32_t bit);
const char *kof_reg_anomaly_name(unsigned index);

#define REG_REGIONS(X)           \
	X(KOF_SCAN_REG_HEADER)   \
	X(KOF_SCAN_REG_KEYS)     \
	X(KOF_SCAN_REG_VALUES)   \
	X(KOF_SCAN_REG_HEX)      \
	X(KOF_SCAN_REG_COMMENT)  \
	X(KOF_SCAN_REG_UNCLAIMED)

extern const uint32_t kof_reg_region_bits[];
#define KOF_REG_REGION_COUNT 6u   /* asserted against the array in the .c */

#endif /* KOFENG_REG_PARSE_H */
