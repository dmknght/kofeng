/*
 * endian.h - one byte order for the objects the engine compares: the canonical
 * form of a big-endian ELF.
 *
 * WHY THERE IS A CANONICAL FORM. A rule is cut from the build a researcher has,
 * and for the architectures an IoT botnet is cross-compiled to that is almost
 * always the little-endian one. The same program built for the big-endian twin
 * of an architecture is the same instruction stream in the other byte order:
 * MIPS and MIPSEL, ARM and ARMEB, PowerPC64 BE and LE, SH4 and SH4EB, MicroBlaze
 * and its LE twin hold identical instruction WORDS, stored the other way round.
 * A byte pattern, a block hash and a string cluster are all byte-level, so a
 * rule cut from one is blind to the other unless the bytes are put in ONE order
 * first.
 *
 * WHICH ORDER: LITTLE. The direction is a choice and this is the evidence for
 * it. Over the two corpora (the 254-file set and the 300-file subset: 347 ELF
 * objects) 319 objects are little-endian and 28 big-endian. Of the architectures
 * that exist in both orders (MIPS, ARM, AArch64, PPC64, SH, MicroBlaze) there are
 * 45 little-endian objects and 14 big-endian ones, and every one of the 271 x86
 * objects is little-endian. Rules are cut from the builds researchers have, so the
 * canonical form is the order most of them already speak. An architecture with no
 * little-endian twin (SPARC, m68k, s390x, 32-bit PowerPC, OpenRISC) has nothing
 * to be made equal to, and its canonical form is what it is: big-endian,
 * untouched. Swapping it would buy no match and would make the object disagree
 * with its decoder.
 *
 * WHAT IS SWAPPED, AND ONLY WHAT IS STRUCTURALLY KNOWN. A byte order is a
 * property of a field, and a byte stream does not say where its fields are. A
 * string is bytewise; a 4-byte word might be an integer or four characters. So
 * nothing is swapped on a guess. The plan names exactly:
 *
 *   code        the executable sections (the program headers' PF_X segments when
 *               there is no section table), in the instruction unit of the
 *               architecture: 4 bytes (MIPS, ARM state, PPC64, MicroBlaze), 2
 *               (SH, MIPS16 / microMIPS, ARM Thumb, told by mapping symbols).
 *               None for ARM BE8 and AArch64: their instructions are
 *               little-endian already, whatever the data is.
 *   headers     the ELF header, the program header table, the section header
 *               table.
 *   tables      symbol tables, REL / RELA, the dynamic table, SysV and GNU hash
 *               tables, symbol versions, init / fini arrays, note headers, the
 *               MIPS register info and the ARM unwind index.
 *   wide text   UTF-16BE runs in the bytes the plan does not claim, turned into
 *               UTF-16LE, so the engine's one narrowing (UTF-16LE to ASCII) then
 *               reads them. kgenome_endian_wide.
 *
 * AND WHAT IS NOT: the multi-byte values of the data sections (.data, .rodata,
 * the GOT, vtables, jump tables in read-only data, relocation targets), because
 * their widths are not in the file; strings, ever; the contents of a note; the
 * ARM attributes section; the symbol-version definition and need records; a
 * string that sits inside an executable section (it is swapped with its
 * words); and any unit that straddles the end of a span. Those stay as the
 * build wrote them. A rule that depends on one of them is a rule about the big
 * -endian build and keeps matching the original object, which is always
 * scanned as well.
 *
 * THE SWAP IS AN INVOLUTION. Every span is swapped field by field, so applying
 * the same plan twice gives the original bytes back - the round trip the tests
 * pin - and a plan made from a canonical object is empty, so normalising twice
 * does nothing. Spans are disjoint and sorted; where an object's own structure
 * makes two overlap, the one named earlier in the list above keeps its bytes, the
 * other is dropped and counted (`dropped`). The one case that is not hostile is a
 * stripped object, whose only code is a segment that starts at the ELF header: the
 * header tables are claimed first there and the code goes around them, and around
 * the string literals the segment holds (a run of 8 or more printable bytes,
 * widened to whole units), because a string swapped by words is unreadable.
 *
 * NOTHING MOVES. The swap changes bytes in place, so every offset the object has
 * means what it meant: the offset map of the view built over it is the one the
 * rest of the normaliser already builds, and the swap adds nothing to it.
 */
#ifndef KGENOME_IMAGE_ENDIAN_H
#define KGENOME_IMAGE_ENDIAN_H

#include <stdint.h>

#include <genotype/image/obj.h>
#include <kofcore.h>
#include "../../kgenome_status.h"

/* The fields of one table entry, at most. */
#define KGENOME_ENDIAN_FIELDS 16u

/*
 * How many spans one plan can hold, and why there is a number at all: a plan
 * grows with what the file declares (a note section of a million records is a
 * million spans), so the plan is bounded - and reports when it was cut
 * (KGENOME_TRUNCATED), because a plan cut short is an object half in each
 * order. Far above what a real object has: the largest plan of the 28 big-endian
 * objects in the corpora holds 31 spans.
 */
#define KGENOME_ENDIAN_MAX_SPANS (1u << 16)

enum kgenome_endian_layout {
	KGENOME_ENDIAN_L_W2 = 0,        /* 2-byte units  */
	KGENOME_ENDIAN_L_W4,            /* 4-byte units  */
	KGENOME_ENDIAN_L_W8,            /* 8-byte units  */
	KGENOME_ENDIAN_L_EHDR32,
	KGENOME_ENDIAN_L_EHDR64,
	KGENOME_ENDIAN_L_PHDR32,
	KGENOME_ENDIAN_L_PHDR64,
	KGENOME_ENDIAN_L_SHDR32,
	KGENOME_ENDIAN_L_SHDR64,
	KGENOME_ENDIAN_L_SYM32,
	KGENOME_ENDIAN_L_SYM64,
	KGENOME_ENDIAN_L_REL32,
	KGENOME_ENDIAN_L_RELA32,
	KGENOME_ENDIAN_L_REL64,
	KGENOME_ENDIAN_L_RELA64,
	KGENOME_ENDIAN_L_MREL64,        /* MIPS64: r_info is a word and four bytes */
	KGENOME_ENDIAN_L_MRELA64,
	KGENOME_ENDIAN_L_DYN32,
	KGENOME_ENDIAN_L_DYN64,
	KGENOME_ENDIAN_L_NOTE,          /* the three words of a note header */
	KGENOME_ENDIAN_L_COUNT
};

struct kgenome_endian_span {
	uint64_t off, len;      /* a file extent; a whole number of entries */
	uint8_t  lay;           /* enum kgenome_endian_layout */
};

struct kgenome_endian_plan {
	struct kgenome_endian_span *v;  /* sorted by off, disjoint; malloc'd */
	uint32_t n, cap;
	/* While the plan is being BUILT the array has a gap of `gap_n` free slots at index
	 * `gap_at`, where the next span goes (endian_plan.c span_add). Both are zero in a
	 * finished plan, whose v[0..n) is contiguous; nothing outside the builder sees a gap. */
	uint32_t gap_at, gap_n;
	uint8_t  code_unit;     /* 0, 2 or 4: the instruction unit swapped in code */
	uint8_t  ident;         /* 1: e_ident[EI_DATA] is turned to little-endian too */
	/* How many spans were refused because the object's own structure put them on
	 * bytes an earlier span owns: a fact about the file, not a limit. */
	uint32_t dropped;
	/* OK, or: TRUNCATED (the plan hit KGENOME_ENDIAN_MAX_SPANS), NOMEM, BAD_INPUT
	 * (a big-endian ELF whose header is cut: nothing swapped). */
	enum kgenome_status status;
};

/*
 * Does this architecture have a little-endian twin the canonical form can be
 * made equal to. The set is MIPS, MIPS64, ARM, AArch64, PPC64, SH, MicroBlaze.
 */
int kgenome_endian_has_twin(unsigned arch);

/*
 * The instruction unit of an object's code: 4, 2, or 0 when its code needs no
 * swap (an architecture with no twin, ARM BE8, AArch64). A property of the
 * object and not of its architecture alone: e_flags says MIPS16 / microMIPS,
 * and EF_ARM_BE8 says the code is already little-endian.
 */
uint32_t kgenome_endian_code_unit(const struct kgenome_obj *obj);

/*
 * Is the object big-endian, with a twin: the one question "does this object
 * have a canonical form other than itself". Cheap and total.
 */
int kgenome_endian_wanted(const struct kgenome_obj *obj);

/*
 * The plan for a big-endian ELF, over the bytes as they are. An empty plan (n
 * of 0, ident 0) is the answer for a little-endian object, a PE, an unparsed
 * object and an architecture with no twin: nothing to do, and status OK. The
 * caller frees with kgenome_endian_plan_free whatever the status.
 */
enum kgenome_status kgenome_endian_plan_build(kof_buf f, const struct kgenome_obj *obj,
					      struct kgenome_endian_plan *out);
void kgenome_endian_plan_free(struct kgenome_endian_plan *p);

/*
 * Apply the plan in place: every span swapped field by field, and e_ident
 * turned. Returns how many fields it changed (a field that reads the same both
 * ways - a zero word - is not a change). An involution - the same plan
 * applied twice restores the bytes - and idempotent on a canonical object,
 * whose plan is empty.
 */
uint64_t kgenome_endian_apply(uint8_t *buf, uint64_t n, const struct kgenome_endian_plan *p);

/*
 * The bytes [off, off + len) of `src` (an object of src_n bytes) as the plan
 * would leave them, written to `dst`, without touching `src`. A unit that
 * straddles either end is swapped whole and the part inside the range is what
 * is written, so the answer equals the same range of the applied object
 * whatever the alignment. How a function of the parent is looked for in a view.
 */
void kgenome_endian_range(uint8_t *dst, const uint8_t *src, uint64_t src_n,
			  uint64_t off, uint64_t len, const struct kgenome_endian_plan *p);

/*
 * The description of the object after the plan: e_ident byte order becomes
 * little-endian when the plan turned it. `info` is a copy the caller owns.
 */
void kgenome_endian_describe(struct kgenome_elf_info *info, const struct kgenome_endian_plan *p);

/*
 * UTF-16BE to UTF-16LE, in the bytes the plan does not claim and `keep` (a
 * bitmap, one bit per byte, NULL for none) does not protect.
 *
 * A run is `min_chars` or more consecutive 2-byte units (00, c) with c
 * printable ASCII, the pair starting at an EVEN file offset. The parity is the
 * detection: a UTF-16 string is 2-aligned, so a big-endian one has its zero at
 * an even offset and a little-endian one at an odd offset, and the two cannot be
 * mistaken for each other the way they are by a scan that starts at any byte -
 * which also makes this idempotent, because the run it writes has its zero at
 * the odd offsets and no longer matches. Each pair of a run is swapped.
 *
 * ONE AMBIGUITY, and it is decided the safe way. A little-endian string at an
 * ODD offset reads, from the next even offset, as a big-endian one. A run
 * therefore does not start on a unit whose zero byte follows a printable byte:
 * that zero is the high byte of the character before it. The price is a big-endian
 * string that follows printable bytes with no terminator or padding between, which
 * is left as it is.
 *
 * `plan` may be NULL. Returns the number of runs swapped. Nothing is allocated.
 */
uint32_t kgenome_endian_wide(uint8_t *buf, uint64_t n, const uint8_t *keep,
			     const struct kgenome_endian_plan *plan, uint32_t min_chars);

#endif /* KGENOME_IMAGE_ENDIAN_H */
