/*
 * clr.h - the regions of a .NET assembly.
 *
 * THE ABI RE-EXPORTS kgenome's TYPE: struct kof_clr_meta, the CLR region bits
 * and the anomaly names describe the structure of the executable and are
 * defined once in libgenome/genotype/image/clr_types.h.
 */
#ifndef KOFMOD_CLR_H
#define KOFMOD_CLR_H

#include <genotype/image/clr_types.h>

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define KOF_SCAN_CLR_BLOB                  KGENOME_SCAN_CLR_BLOB
#define KOF_SCAN_CLR_CLAIMED               KGENOME_SCAN_CLR_CLAIMED
#define KOF_SCAN_CLR_HEADER                KGENOME_SCAN_CLR_HEADER
#define KOF_SCAN_CLR_RESOURCE              KGENOME_SCAN_CLR_RESOURCE
#define KOF_SCAN_CLR_STRINGS               KGENOME_SCAN_CLR_STRINGS
#define KOF_SCAN_CLR_TABLES                KGENOME_SCAN_CLR_TABLES
#define KOF_SCAN_CLR_US                    KGENOME_SCAN_CLR_US
#define kof_clr_meta                       kgenome_clr_meta

#endif /* KOFMOD_CLR_H */
