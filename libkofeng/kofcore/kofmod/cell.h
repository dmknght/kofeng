/*
 * cell.h - reading code without running it, from a module.
 *
 * THE ABI RE-EXPORTS kgenome's TYPE. struct cell_insn, struct cell_operand and
 * the opcode-class vocabulary describe what the analysis reads, so they are
 * defined once in libgenome/celllysis/cell.h (the design note - why a module
 * decodes instead of matching bytes, and why this is pseudo-emulation - is
 * there too). This header keeps the name a module already includes.
 */
#ifndef KOFENG_CELL_H
#define KOFENG_CELL_H

#include "basic.h"
#include <celllysis/cell.h>

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define CELL_JMP                           KGENOME_CELL_JMP
#define CELL_O_MEM                         KGENOME_CELL_O_MEM
#define CELL_XOR                           KGENOME_CELL_XOR
#define KOF_ARCH_ANY                       KGENOME_ARCH_ANY
#define KOF_ARCH_ARC                       KGENOME_ARCH_ARC
#define KOF_ARCH_ARM                       KGENOME_ARCH_ARM
#define KOF_ARCH_ARM64                     KGENOME_ARCH_ARM64
#define KOF_ARCH_COUNT                     KGENOME_ARCH_COUNT
#define KOF_ARCH_CRIS                      KGENOME_ARCH_CRIS
#define KOF_ARCH_LIST(X) KGENOME_ARCH_LIST_(KOF_, X)   /* entries spelled KOF_*: #name is the word */
#define KOF_ARCH_M68K                      KGENOME_ARCH_M68K
#define KOF_ARCH_MICROBLAZE                KGENOME_ARCH_MICROBLAZE
#define KOF_ARCH_MIPS                      KGENOME_ARCH_MIPS
#define KOF_ARCH_MIPS64                    KGENOME_ARCH_MIPS64
#define KOF_ARCH_OR1K                      KGENOME_ARCH_OR1K
#define KOF_ARCH_OTHER                     KGENOME_ARCH_OTHER
#define KOF_ARCH_PPC                       KGENOME_ARCH_PPC
#define KOF_ARCH_PPC64                     KGENOME_ARCH_PPC64
#define KOF_ARCH_RISCV32                   KGENOME_ARCH_RISCV32
#define KOF_ARCH_RISCV64                   KGENOME_ARCH_RISCV64
#define KOF_ARCH_SH                        KGENOME_ARCH_SH
#define KOF_ARCH_SPARC                     KGENOME_ARCH_SPARC
#define KOF_ARCH_SPARC64                   KGENOME_ARCH_SPARC64
#define KOF_ARCH_X86                       KGENOME_ARCH_X86
#define KOF_ARCH_X86_64                    KGENOME_ARCH_X86_64
#define KOF_ARCH_XTENSA                    KGENOME_ARCH_XTENSA
#define KOF_ARCH_X_ENUM                    KGENOME_ARCH_X_ENUM
#define KOF_BROKEN                         KGENOME_BROKEN
#define KOF_NA                             KGENOME_NA
#define cell_insn                          kgenome_cell_insn
#define cell_operand                       kgenome_cell_operand
#define kof_arch                           kgenome_arch

#endif /* KOFENG_CELL_H */
