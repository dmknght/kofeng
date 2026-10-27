/*
 * arch_title.c - kgenome_arch_title (declared in arch.h): the architecture's name and width, for a tool to show.
 */
#include "arch.h"

#include <stddef.h>

const char *kgenome_arch_title(uint8_t arch)
{
	switch (arch) {
	case KGENOME_ARCH_ANY:       return "any";
	case KGENOME_ARCH_X86:       return "x86 32-bit";
	case KGENOME_ARCH_X86_64:    return "x86-64 64-bit";
	case KGENOME_ARCH_ARM:       return "ARM 32-bit";
	case KGENOME_ARCH_ARM64:     return "AArch64 64-bit";
	case KGENOME_ARCH_RISCV64:   return "RISC-V 64-bit";
	case KGENOME_ARCH_MIPS:      return "MIPS 32-bit";
	case KGENOME_ARCH_PPC64:     return "PowerPC 64-bit";
	case KGENOME_ARCH_MIPS64:    return "MIPS 64-bit";
	case KGENOME_ARCH_PPC:       return "PowerPC 32-bit";
	case KGENOME_ARCH_RISCV32:   return "RISC-V 32-bit";
	case KGENOME_ARCH_ARC:       return "ARC 32-bit";
	case KGENOME_ARCH_SH:        return "SuperH 32-bit";
	case KGENOME_ARCH_M68K:      return "Motorola 68000 32-bit";
	case KGENOME_ARCH_SPARC:     return "SPARC 32-bit";
	case KGENOME_ARCH_SPARC64:   return "SPARC V9 64-bit";
	case KGENOME_ARCH_MICROBLAZE:return "MicroBlaze 32-bit";
	case KGENOME_ARCH_XTENSA:    return "Xtensa 32-bit";
	case KGENOME_ARCH_CRIS:      return "CRIS 32-bit";
	case KGENOME_ARCH_OR1K:      return "OpenRISC 32-bit";
	default:                     return NULL;
	}
}
