/* ppc_private.h - the layout of the PowerPC decode tables. Shared by ppc.c and ppc_tab.c, and by nobody else. */
#ifndef KGENOME_GENOTYPE_PPC_PRIVATE_H
#define KGENOME_GENOTYPE_PPC_PRIVATE_H

#include <stdint.h>

/*
 * A ROW is "a word matches when (word & mask) == val". A list is tried in order and its LAST row
 * has mask 0 and the identity INVALID (or UNSUPPORTED), so something always answers; priority is
 * the order. Only the primary opcodes whose extended opcode is not a plain index use a list
 * (19, 30, 59, 63, 17); opcode 31 is an index of 1024 on the ten-bit extended opcode.
 */
struct kgenome_ppc_row {
	uint32_t mask, val;
	uint16_t id;
};

enum kgenome_ppc_pk {
	KGENOME_PPC_PK_ID = 0,          /* the opcode alone names the identity */
	KGENOME_PPC_PK_ROWS,            /* a row list */
	KGENOME_PPC_PK_X31              /* index (word >> 1) & 1023 into kgenome_ppc_x31 */
};

struct kgenome_ppc_prim {
	uint8_t  kind;                  /* enum kgenome_ppc_pk */
	uint16_t id;                    /* PK_ID */
	const struct kgenome_ppc_row *rows;     /* PK_ROWS */
};

extern const struct kgenome_ppc_prim kgenome_ppc_prim[64];
extern const uint16_t kgenome_ppc_x31[1024];
extern const char *const kgenome_ppc_names[];
extern const uint8_t kgenome_ppc_attr[];

#endif /* KGENOME_GENOTYPE_PPC_PRIVATE_H */
