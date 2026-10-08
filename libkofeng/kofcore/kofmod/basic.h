/*
 * basic.h - the two sentinels and the architecture list.
 *
 * Split out of kofsig.h because the code reader (kofmod/cell.h, and the library
 * behind it) needs exactly these three things from the module API and nothing
 * else: a value for "no target", and which instruction set the bytes are. Taking
 * them through kofsig.h meant a decoder included the whole rule vocabulary - the
 * views, the verdict levels, the vtable - to read a constant. Nothing moved: the
 * definitions are byte for byte what they were, and kofsig.h includes this.
 */
#ifndef KOFENG_BASIC_H
#define KOFENG_BASIC_H

#include <stdint.h>

/*
 * Two sentinels for scalar facts, kept distinct because they lead to different
 * decisions. A script has no entry point at all, which is unremarkable; an ELF
 * that declares one the parser cannot resolve is a strong signal. A single
 * "unknown" value would throw that difference away.
 */
#define KOF_NA     UINT64_MAX          /* concept does not apply to this object */
#define KOF_BROKEN (UINT64_MAX - 1)    /* applies, but could not be determined */

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
 * source writes KOF_ARCH_X86_64 and the builder has to turn that back into a
 * value, an editor offers the set to pick from, and the build script used to
 * keep an eleventh-hand copy of its own.
 *
 * That copy is why this is a macro now. It listed the architectures in order
 * and matched them as substrings, so KOF_ARCH_X86 - a PREFIX of KOF_ARCH_X86_64
 * - set both bits, and every x86-64-only rule also ran on x86 objects. It had
 * also stopped three architectures short of this list. Neither could be caught
 * by a compiler while the list existed twice.
 *
 * X(NAME, value, short word). The short words are kept to the width of the
 * thing they describe rather than spelled out; x86 and x64 keep their
 * conventional spellings because those are what everyone already reads, and the
 * rest follow the same shape so the set can be scanned at a glance.
 */
#define KOF_ARCH_LIST(X)                                                     \
	X(KOF_ARCH_ANY,     0,  "any")   /* script, text, bytecode */        \
	X(KOF_ARCH_X86,     1,  "x86")                                       \
	X(KOF_ARCH_X86_64,  2,  "x64")                                       \
	X(KOF_ARCH_ARM,     3,  "a32")                                       \
	X(KOF_ARCH_ARM64,   4,  "a64")                                       \
	X(KOF_ARCH_RISCV64, 5,  "r64")                                       \
	X(KOF_ARCH_MIPS,    6,  "m32")                                       \
	X(KOF_ARCH_PPC64,   7,  "p64")                                       \
	X(KOF_ARCH_MIPS64,  8,  "m64")                                       \
	X(KOF_ARCH_PPC,     9,  "p32")                                       \
	X(KOF_ARCH_RISCV32, 10, "r32")                                       \
	X(KOF_ARCH_ARC,     11, "arc")   /* Synopsys ARC - an IoT botnet
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
	X(KOF_ARCH_SH,        12, "sh")    /* Renesas SuperH; Mirai's "sh4" */\
	X(KOF_ARCH_M68K,      13, "68k")   /* Motorola 68000                */\
	X(KOF_ARCH_SPARC,     14, "spc")   /* v8 and v8plus                 */\
	X(KOF_ARCH_SPARC64,   15, "spc64") /* v9                            */\
	X(KOF_ARCH_MICROBLAZE,16, "mbz")                                     \
	X(KOF_ARCH_XTENSA,    17, "xts")                                     \
	X(KOF_ARCH_CRIS,      18, "cris")  /* Axis ETRAX                    */\
	X(KOF_ARCH_OR1K,      19, "or1k")  /* OpenRISC 1000                 */

enum kof_arch {
#define KOF_ARCH_X_ENUM(name, val, word) name = val,
	KOF_ARCH_LIST(KOF_ARCH_X_ENUM)
#undef KOF_ARCH_X_ENUM
	KOF_ARCH_OTHER   = 255 /* recognised format, architecture not in this list */
};

/* How many the list names, which is not the largest value: OTHER is outside it
 * on purpose. A mask has one bit per member, so this is also its width. */
#define KOF_ARCH_COUNT 20u

#endif /* KOFENG_BASIC_H */
