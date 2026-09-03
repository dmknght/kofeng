/*
 * kofsym.h - a file's symbol table, re-presented in one fixed layout.
 *
 * WHY RE-PRESENT IT AT ALL.
 *
 * The symbols are already in the file and already scannable: .symtab and .strtab
 * are non-ALLOC sections, so NOLOAD covers them and a signature can match their
 * bytes today. That is what makes the existing SCLoader rule fragile - it
 * matches "\0shellcode\0", which is a STRING TABLE byte run. Rename the variable
 * and the rule dies; a debug string elsewhere in NOLOAD that happens to spell
 * the same thing matches it for free.
 *
 * What a rule actually wants to say is "a GLOBAL OBJECT of 949 bytes", and the
 * file does hold that - as st_info's two nibbles and st_size, inside a 24-byte
 * Elf64_Sym. Matching THAT directly has two problems. The layout is ELF64's:
 * ELF32 packs the same fields in 16 bytes in a different order, and a PE export
 * table shares none of it. And the NAME is not there - st_name is an index into
 * another section - so name and attributes can never be one pattern.
 *
 * So the records below are OURS. Fixed stride, every field at a constant offset,
 * the name inline. A rule can then say type, bind, size and name in a single
 * pattern, and mean it about a symbol rather than about some bytes that happened
 * to spell it.
 *
 * THE VALUES ARE ELF'S, THOUGH, AND DELIBERATELY.
 *
 * type, bind and visibility carry the numbers ELF itself defines - STT_OBJECT is
 * 1 here because it is 1 in the ABI, STT_SECTION is 3 and STT_FILE is 4 in that
 * order because that is the order the standard fixed. Inventing a private
 * numbering would buy nothing and cost everyone who writes a rule a translation
 * table, and it would rot the first time a value was added. A format with its
 * own vocabulary - PE's export ordinals - maps INTO these, which is the same
 * direction kof_inspect_subtype_name already goes.
 *
 * AN EMPTY BLOCK IS A NORMAL ANSWER. A stripped binary has no .symtab, so the
 * count is zero and the block is a header alone. That is not a failure to
 * report: it is what the file says. NOLOAD behaves the same way and for the same
 * reason.
 */

#ifndef KOF_KOFSYM_H
#define KOF_KOFSYM_H

#include <stdint.h>
#include <kofcore.h>          /* kof_buf */

/*
 * The block: one header, then `count` records of KOF_SYM_RECLEN bytes.
 *
 * reclen is in the header rather than assumed by the reader, so a record that
 * grows later is a version bump and not a silent misparse of every field after
 * the one that moved.
 */
#define KOF_SYM_MAGIC0  'K'
#define KOF_SYM_MAGIC1  'S'
#define KOF_SYM_MAGIC2  'Y'
#define KOF_SYM_MAGIC3  'M'
#define KOF_SYM_VERSION 1u
#define KOF_SYM_HDRLEN  16u
#define KOF_SYM_RECLEN  64u
#define KOF_SYM_NAMELEN 40u     /* inline, NUL-padded, truncated if longer */

/* Header field offsets. */
#define KOF_SYM_H_MAGIC     0u  /* 4  "KSYM"                                  */
#define KOF_SYM_H_VERSION   4u  /* 2  KOF_SYM_VERSION                         */
#define KOF_SYM_H_RECLEN    6u  /* 2  KOF_SYM_RECLEN                          */
#define KOF_SYM_H_COUNT     8u  /* 4  records that follow                     */
#define KOF_SYM_H_ORIGIN   12u  /* 1  KOF_SYM_ORIGIN_*                        */
#define KOF_SYM_H_TRUNC    13u  /* 1  1 when the cap stopped it short         */
#define KOF_SYM_H_RESERVED 14u  /* 2  zero                                    */

/* Record field offsets. Every one is a constant; nothing here is searched for. */
#define KOF_SYM_R_TYPE      0u  /* 1  STT_*  - ELF's numbering                */
#define KOF_SYM_R_BIND      1u  /* 1  STB_*                                   */
#define KOF_SYM_R_VIS       2u  /* 1  STV_*                                   */
#define KOF_SYM_R_FLAGS     3u  /* 1  KOF_SYM_F_*                             */
#define KOF_SYM_R_SHNDX     4u  /* 2  section index; 0 is ELF's SHN_UNDEF,   */
                                /*    0xffff any reserved index (ABS, COMMON) */
#define KOF_SYM_R_RESERVED  6u  /* 2  zero                                    */
#define KOF_SYM_R_VALUE     8u  /* 8  address, little endian                  */
#define KOF_SYM_R_SIZE     16u  /* 8  size, little endian                     */
#define KOF_SYM_R_NAME     24u  /* 40 NUL-padded                              */

/* Which table the block was built from. */
enum kof_sym_origin {
	KOF_SYM_ORIGIN_NONE   = 0,
	KOF_SYM_ORIGIN_SYMTAB = 1,   /* ELF .symtab - full, removed by strip     */
	KOF_SYM_ORIGIN_DYNSYM = 2    /* ELF .dynsym - what dynamic linking needs */
};

/*
 * Facts the record states that the ELF fields only imply.
 *
 * DEFINED and UNDEFINED are st_shndx tested once here rather than by every rule
 * that cares, and IN_WRITABLE / IN_EXEC are the flags of the section the symbol
 * lands in - which is the question "is this data the program can jump to", and
 * the one a loader heuristic actually asks.
 */
enum kof_sym_flag {
	KOF_SYM_F_DEFINED     = 1u << 0,
	KOF_SYM_F_UNDEFINED   = 1u << 1,   /* an import                          */
	KOF_SYM_F_IN_WRITABLE = 1u << 2,
	KOF_SYM_F_IN_EXEC     = 1u << 3,
	KOF_SYM_F_HAS_SIZE    = 1u << 4
};

/* ELF's own values, repeated so a reader of this file need not go and get them.
 * They are the ABI's; do not renumber. */
enum { KOF_STT_NOTYPE = 0, KOF_STT_OBJECT = 1, KOF_STT_FUNC = 2,
       KOF_STT_SECTION = 3, KOF_STT_FILE = 4, KOF_STT_COMMON = 5,
       KOF_STT_TLS = 6 };
enum { KOF_STB_LOCAL = 0, KOF_STB_GLOBAL = 1, KOF_STB_WEAK = 2 };
enum { KOF_STV_DEFAULT = 0, KOF_STV_INTERNAL = 1, KOF_STV_HIDDEN = 2,
       KOF_STV_PROTECTED = 3 };

/*
 * How many records one block may hold.
 *
 * Symbol counts run to 43912 on real binaries - elf.h says so and that is why
 * the parse does not store them - and 43912 records is 2.8MB of block for a file
 * nobody asked a symbol question about. The cap bounds it; the header's
 * `truncated` byte says when it bit, so a reader is never quietly told a short
 * table is the whole one.
 */
#define KOF_SYM_MAX_RECS 4096u
#define KOF_SYM_MAX_BYTES (KOF_SYM_HDRLEN + KOF_SYM_MAX_RECS * KOF_SYM_RECLEN)

/*
 * Build the block for an ELF. Returns the bytes written - never less than the
 * header, so an empty answer is still a block a reader can parse. `cap` bounds
 * it; KOF_SYM_MAX_BYTES is enough for the record cap.
 */
struct kof_elf_info;
uint32_t kof_elf_syms(kof_buf file, const struct kof_elf_info *e,
		      uint8_t *out, uint32_t cap);

#endif /* KOF_KOFSYM_H */
