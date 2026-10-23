/*
 * codemap.h - where an object's code branches, calls and enters the kernel, and which of those places point at one another.
 *
 * ONE LINEAR READ of the object's code, through the same cursor and the same register model the diagnose routes use (celllysis), kept as a
 * table that a viewer, a report or a later analysis can ask. It answers four questions and no more: what each branch instruction is and where it
 * goes (jump, conditional jump, loop, call), which of them goes BACKWARD, what number a syscall instruction carries, and who
 * refers to a given place (the cross references). A name for a place - a symbol, an import - is not the lib's to give: it holds offsets and the
 * engine that owns the symbol table says what they are called.
 *
 * WHAT A SYSCALL NUMBER IS HERE. The constant the register model holds in the number register at the instruction, within STRAIGHT-LINE code: the
 * model is dropped at every branch target and after every branch, because a value that arrives from two predecessors is not a value. A number the
 * model does not hold - it came from a caller, or from memory - is not guessed: the reference says it is unknown.
 *
 * NOT CAPPED. The table is as long as the object's code makes it; a limit on the result is a limit on evidence. What bounds it is the object's own size.
 */
#ifndef KGENOME_CODEMAP_H
#define KGENOME_CODEMAP_H

#include <stdint.h>

#include "../genotype/image/obj.h"
#include "../kgenome_status.h"

struct kgenome_elf_relocs;

enum kgenome_codemap_kind {
	KGENOME_CM_JMP = 1,     /* unconditional jump */
	KGENOME_CM_JCC,         /* conditional jump */
	KGENOME_CM_LOOP,        /* loop/jecxz and kin: a conditional jump that counts */
	KGENOME_CM_CALL,
	KGENOME_CM_RET,         /* ends a straight line; carries no target */
	KGENOME_CM_SYSCALL      /* syscall, sysenter, int 0x80: `nr` is the number when KGENOME_CMF_NR */
};

/* Backward: the target is at or before the branch. A loop's back edge is one; a backward branch is not always a loop (that needs the flow graph, which this does not build). */
#define KGENOME_CMF_BACK     (1u << 0)
/* Through a register or memory: there is no target in the encoding. */
#define KGENOME_CMF_INDIRECT (1u << 1)
/* The number of a SYSCALL is in `nr`. */
#define KGENOME_CMF_NR       (1u << 2)
/* The target is a hole a relocation fills: the file says nothing about where this goes, the relocation's symbol does. */
#define KGENOME_CMF_RELOC    (1u << 3)
/* int 0x80 and not syscall: the number is the 32-bit table's whatever the object's width. */
#define KGENOME_CMF_INT80    (1u << 4)
/* A RET that pops its caller's arguments (`ret imm16`, i386 stdcall): `nr` is the number of bytes. */
#define KGENOME_CMF_POP      (1u << 5)

struct kgenome_codemap_ref {
	uint64_t at;            /* the instruction's file offset */
	uint64_t to;            /* where it goes, a file offset; KGENOME_BROKEN when indirect, outside the object or a relocation's */
	uint32_t nr;            /* a syscall's number, when KGENOME_CMF_NR; the bytes a RET pops, when KGENOME_CMF_POP */
	uint8_t  len;           /* the instruction's length */
	uint8_t  kind;          /* enum kgenome_codemap_kind */
	uint8_t  flags;         /* KGENOME_CMF_* */
	uint8_t  _pad;
};

struct kgenome_codemap {
	struct kgenome_codemap_ref *v;  /* every branch, call, ret and syscall, in order of `at` */
	uint32_t n;
	uint32_t *by_to;                /* indexes into v of those with a target, ordered by (to, at) */
	uint32_t n_to;
	/* KGENOME_OK, or KGENOME_NOMEM: short for want of memory, not for want of code. */
	enum kgenome_status status;
};

/*
 * Read the object's code - the executable segments of an ELF, the code sections of a PE, or the whole buffer for anything else (a payload with no
 * header is all code) - and fill `out`. `relocs`, when not NULL, is the object's CODE relocation table (kgenome_elf_reloc_table): a branch whose
 * displacement a relocation patches is flagged KGENOME_CMF_RELOC and given no target. Returns 1 when `out` holds an answer (possibly empty), 0 when
 * the architecture has no decoder or memory was refused; `out` is then empty and owns nothing. Free it with kgenome_codemap_free.
 */
int kgenome_codemap_build(const struct kgenome_obj *obj, const uint8_t *base, uint64_t size,
			  const struct kgenome_elf_relocs *relocs, struct kgenome_codemap *out);
void kgenome_codemap_free(struct kgenome_codemap *m);

/* The reference of the instruction at `at`, or NULL. */
const struct kgenome_codemap_ref *kgenome_codemap_at(const struct kgenome_codemap *m, uint64_t at);

/*
 * Who refers to `to`: how many references have it as their target, and the first of them as an index into the by_to order. Reference k of them is
 * m->v[m->by_to[first + k]]. Zero for a place nothing goes to.
 */
uint32_t kgenome_codemap_to(const struct kgenome_codemap *m, uint64_t to, uint32_t *first);

#endif /* KGENOME_CODEMAP_H */
