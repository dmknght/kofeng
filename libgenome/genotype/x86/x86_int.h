/* x86_int.h - the layout of the generated tables. Shared by x86.c and the
 * generated x86_tab.c, and by nobody else. */
#ifndef KOF_GENOTYPE_X86_INT_H
#define KOF_GENOTYPE_X86_INT_H

#include <stdint.h>

/* What one resolved encoding is. The operand templates, sizes and length tuples
 * are shared between leaves; a leaf names them by index. */
struct gt_x86_leaf {
	uint16_t id;
	uint16_t cat;
	uint16_t ops;           /* index of the first operand template        */
	uint8_t  nops;
	uint8_t  cond;
	uint8_t  mand;          /* bit 0: 66, bit 1: F2, bit 2: F3 are the opcode */
	uint8_t  flags;         /* GL_X86_*                                   */
	uint8_t  lenk;          /* index into gt_x86_lenk                     */
	uint8_t  opszk;         /* index into gt_x86_tri: effective operand mode */
	uint16_t vmk;           /* index into gt_x86_vmask (read only if GL_X86_VMASK) */
	uint8_t  dist;          /* registers that must differ: see x86_gen.c      */
	uint8_t  nexp;          /* explicit operands: they come first             */
	uint16_t wgpr;          /* general registers written without being named, bit per register */
	uint8_t  nform;         /* explicit operands in the instruction's definition (a string op counts its [rdi]) */
	uint16_t mnk;           /* index into gt_x86_mnk: the mnemonic, per size variant */
	uint8_t  pf, pf2;       /* what the text shows: GP_X86_* and GQ_X86_* below */
};

/* pf: which prefixes the text names, and the EVEX decorations an instruction takes. */
#define GP_X86_REP   0x01u
#define GP_X86_REPC  0x02u
#define GP_X86_BND   0x04u
#define GP_X86_XACQ  0x08u
#define GP_X86_XREL  0x10u
#define GP_X86_SAE   0x20u
#define GP_X86_ER    0x40u
/* pf2: what a LOCK (xacquire, xrelease) or a segment prefix (branch hint, do-not-track) adds. */
#define GQ_X86_XACQ_LOCK 0x01u
#define GQ_X86_XREL_LOCK 0x02u
#define GQ_X86_BHINT     0x04u
#define GQ_X86_DNT       0x08u

#define GL_X86_MODRM  0x01u     /* has a ModRM byte                           */
#define GL_X86_MOFFS  0x02u     /* has a moffs                                */
#define GL_X86_LOCK   0x04u     /* decodes with a LOCK prefix                 */
#define GL_X86_NOMEM  0x08u     /* ModRM present but a memory form takes no SIB or displacement */
#define GL_X86_REPEATED 0x40u   /* a string instruction run under REP: it repeats up to rcx times */
#define GL_X86_VMASK  0x20u     /* some size/address variants of this leaf are not valid */
#define GL_X86_REGCHK 0x10u     /* has a CR, DR or BND register operand: its number is checked */

/* One operand of a leaf, abstracted from where it sits in the instruction. */
struct gt_x86_tpl {
	uint8_t  te;            /* type | enc << 4                            */
	uint8_t  acc, flags, rtype;
	uint8_t  ad;            /* a register whose size is the address size  */
	uint8_t  memf, seg, base, cnt;
	uint8_t  szk, rszk, rawk;  /* indexes into gt_x86_tri                 */
	uint8_t  ek;            /* a gather's element size, per size variant: index into gt_x86_tri */
	uint32_t reg;           /* register number, or the constant           */
};

/* Selectors a node can switch on: four outer dimensions, then one bit at a time
 * of each inner axis. */
enum {
	GK_X86_PP, GK_X86_MOD, GK_X86_REG, GK_X86_RM,
	GK_X86_OB0, GK_X86_OB1, GK_X86_OB2,
	GK_X86_AB0, GK_X86_AB1, GK_X86_AB2, GK_X86_AB3
};

/* The number of size variants a leaf's length and size tuples are indexed by. */
#define GT_X86_NOSZ 8

extern const struct gt_x86_leaf gt_x86_leaves[];
extern const struct gt_x86_tpl  gt_x86_tpls[];
extern const uint16_t           gt_x86_tri[][8];
extern const uint8_t            gt_x86_lenk[][32];
extern const char *const        gt_x86_mnem[];
extern const uint16_t           gt_x86_mnk[][8];
extern const uint8_t            gt_x86_fix[][8];
extern const uint8_t            gt_x86_vmask[][16];
extern const uint16_t *const     gt_x86_space_nodes[4];
extern const uint16_t           gt_x86_root[2][17][256];

#endif
