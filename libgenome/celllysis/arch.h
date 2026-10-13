/*
 * arch.h - the two sentinels and the architecture list (defined by libgenome;
 * the engine re-exports it as <kofmod/basic.h>).
 *
 * Split out of kofsig.h because the code reader (kofmod/cell.h, and the library
 * behind it) needs exactly these three things from the module API and nothing
 * else: a value for "no target", and which instruction set the bytes are. Taking
 * them through kofsig.h meant a decoder included the whole rule vocabulary - the
 * views, the verdict levels, the vtable - to read a constant. Nothing moved: the
 * definitions are byte for byte what they were, and kofsig.h includes this.
 */
#ifndef KGENOME_ARCH_H
#define KGENOME_ARCH_H

#include <stdint.h>

/*
 * Two sentinels for scalar facts, kept distinct because they lead to different
 * decisions. A script has no entry point at all, which is unremarkable; an ELF
 * that declares one the parser cannot resolve is a strong signal. A single
 * "unknown" value would throw that difference away.
 */
#define KGENOME_NA     UINT64_MAX          /* concept does not apply to this object */
#define KGENOME_BROKEN (UINT64_MAX - 1)    /* applies, but could not be determined */

/*
 * Architecture, normalised across formats.
 *
 * This is the only place a module can ask about architecture without importing
 * a format header, so the values must mean the same thing everywhere. Format
 * specific machine constants (EM_AARCH64, IMAGE_FILE_MACHINE_ARM64) stay in
 * their own headers: they are not comparable across formats, and pretending
 * otherwise would produce a shared enum that is wrong for every member.
 *
 * Width is derivable from the value, which is why there is no separate bits
 * field: arch implies width, width does not imply arch.
 */
/*
 * THE LIST, ONCE.
 *
 * Written as a macro rather than an enum body because four things need it and
 * only one of them is the enum: a finding prints the short word, a signature
 * source writes KGENOME_ARCH_X86_64 and the builder has to turn that back into a
 * value, an editor offers the set to pick from, and the build script used to
 * keep an eleventh-hand copy of its own.
 *
 * That copy is why this is a macro now. It listed the architectures in order
 * and matched them as substrings, so KGENOME_ARCH_X86 - a PREFIX of KGENOME_ARCH_X86_64
 * - set both bits, and every x86-64-only rule also ran on x86 objects. It had
 * also stopped three architectures short of this list. Neither could be caught
 * by a compiler while the list existed twice.
 *
 * X(NAME, value, short word). The short words are kept to the width of the
 * thing they describe rather than spelled out; x86 and x64 keep their
 * conventional spellings because those are what everyone already reads, and the
 * rest follow the same shape so the set can be scanned at a glance.
 */
/* The prefix is a parameter so the same list is read with two spellings: KGENOME_ARCH_LIST(X) below
 * hands the enumerators their own name, and the ABI list KGENOME_ARCH_LIST(X) in <kofmod/cell.h>
 * hands a consumer that STRINGIFIES the name the word a signature source writes. */
#define KGENOME_ARCH_LIST_(P, X)                                                     \
	X(P##ARCH_ANY,     0,  "any")   /* script, text, bytecode */        \
	X(P##ARCH_X86,     1,  "x86")                                       \
	X(P##ARCH_X86_64,  2,  "x64")                                       \
	X(P##ARCH_ARM,     3,  "a32")                                       \
	X(P##ARCH_ARM64,   4,  "a64")                                       \
	X(P##ARCH_RISCV64, 5,  "r64")                                       \
	X(P##ARCH_MIPS,    6,  "m32")                                       \
	X(P##ARCH_PPC64,   7,  "p64")                                       \
	X(P##ARCH_MIPS64,  8,  "m64")                                       \
	X(P##ARCH_PPC,     9,  "p32")                                       \
	X(P##ARCH_RISCV32, 10, "r32")                                       \
	X(P##ARCH_ARC,     11, "arc")   /* Synopsys ARC - an IoT botnet
					  * target, and a whole tier of them
					  * read as "other" without it */      \
	/*
	 * THE REST OF THE CROSS-COMPILE SET, for the same reason as ARC.
	 *
	 * A botnet source ships one makefile per target and these are on it.
	 * Counted over 11264 ELF objects in Bazaar.2026.08 and MalwareLab,
	 * the architectures this list did not name were:
	 *
	 *     SH          350      MicroBlaze   33      Xtensa      14
	 *     M68K        345      SPARCv9      25      LoongArch    3
	 *     SPARC       256      CRIS         16      BPF          3
	 *     S390         22      OpenRISC     16
	 *
	 * 1083 objects, every one of them reported "other", which is honest
	 * and useless: KOF_TARGET_ARCH cannot name them, so no rule can be
	 * written that declines anything else. The eight below cover 1055 of
	 * the 1083 and are each a target a Mirai or Gafgyt makefile builds.
	 *
	 * S390, LoongArch and BPF are LEFT OUT on purpose - a mainframe, a
	 * desktop ISA and an in-kernel bytecode that is not a program at all
	 * (the three here are `pr0be.boop.o`, an eBPF object file). Naming an
	 * architecture nobody will write a rule against is a word to maintain
	 * and nothing else.
	 *
	 * SPARC AND SPARCv9 ARE TWO, where ARC's three machine numbers were
	 * one. ARC 45, 93 and 195 are the same instruction set under three
	 * toolchain spellings; SPARCv9 is the 64-bit ISA, and this list
	 * already splits every other architecture that has two widths -
	 * m32/m64, p32/p64, r32/r64, a32/a64.
	 */                                                                  \
	X(P##ARCH_SH,        12, "sh")    /* Renesas SuperH; Mirai's "sh4" */\
	X(P##ARCH_M68K,      13, "68k")   /* Motorola 68000                */\
	X(P##ARCH_SPARC,     14, "spc")   /* v8 and v8plus                 */\
	X(P##ARCH_SPARC64,   15, "spc64") /* v9                            */\
	X(P##ARCH_MICROBLAZE,16, "mbz")                                     \
	X(P##ARCH_XTENSA,    17, "xts")                                     \
	X(P##ARCH_CRIS,      18, "cris")  /* Axis ETRAX                    */\
	X(P##ARCH_OR1K,      19, "or1k")  /* OpenRISC 1000                 */
#define KGENOME_ARCH_LIST(X) KGENOME_ARCH_LIST_(KGENOME_, X)

enum kgenome_arch {
#define KGENOME_ARCH_X_ENUM(name, val, word) name = val,
	KGENOME_ARCH_LIST(KGENOME_ARCH_X_ENUM)
#undef KGENOME_ARCH_X_ENUM
	KGENOME_ARCH_OTHER   = 255 /* recognised format, architecture not in this list */
};

/* How many the list names, which is not the largest value: OTHER is outside it
 * on purpose. A mask has one bit per member, so this is also its width. */
#define KGENOME_ARCH_COUNT 20u

#endif /* KGENOME_ARCH_H */
