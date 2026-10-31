/*
 * callnames.h - the engine's side of the call-name table (kgenome_callnames, libgenome/phenotype/callnames.h): which places in an object's code stand for an
 * imported function, and how each is SPELLED. The lib holds positions; this holds the spelling, once, so a viewer and the code notes say an import the same way.
 *
 * ON REQUEST, ONCE PER OBJECT, like kof_codenotes_build: a scan does not build it. The caller keeps the table on the object and asks for a name by file offset:
 * the branch's target when it is direct (a call to a PLT stub or a PE thunk), the instruction's own offset when it is indirect (`call [slot]`).
 *
 * SPELLING. ELF: `name@plt` for a stub, `name@got` for an instruction that goes through its GOT slot itself. PE: the import's own spelling in the symbol block,
 * `dll!name` or `dll!#ordinal` (kof_pe_import_spell, the one function both use).
 */
#ifndef KOFENG_CALLNAMES_H
#define KOFENG_CALLNAMES_H

#include <stddef.h>
#include <stdint.h>

#include <kofmod/kofsig.h>
#include <phenotype/callnames.h>

/* Can the engine resolve call names for this object (an x86 or x86-64 ELF or PE with a parsed header). */
int kof_callnames_applicable(const struct kof_obj_ctx *ctx);

/*
 * Build the table for the object `ctx` describes, over its bytes `data`. `led`, when not NULL, is the account the table is charged to; give it back with
 * kgenome_callnames_free(out, led). Returns 1 when `out` holds an answer (possibly empty), 0 when the object is not one the lib resolves (`out->status` says
 * why: UNSUPPORTED for another architecture, BAD_INPUT for no header). `out->status` otherwise says whether the table is whole.
 */
int kof_callnames_build(const struct kof_obj_ctx *ctx, kof_buf data, struct kgenome_ledger *led, struct kgenome_callnames *out);

/*
 * What a branch is asking: the name of the place a DIRECT branch lands on (TARGET: `off` is the target, and only a stub or thunk answers - a call to the middle of
 * a function that happens to hold a `call [slot]` is not a call to the import), or of an INDIRECT branch through a slot (SITE: `off` is the instruction itself,
 * and only an instruction that goes through the slot answers; a stub's own `jmp [slot]` does not, its place already carries the name).
 */
enum kof_callname_via {
	KOF_CALLNAME_VIA_TARGET = 1,
	KOF_CALLNAME_VIA_SITE
};

/* The spelled name for the branch described by `via` and `off` into `out` (cap bytes, NUL-ended): 1 when there is one, 0 when there is none. `data` is the object's bytes. */
int kof_callnames_name(const struct kgenome_callnames *t, kof_buf data, enum kof_callname_via via, uint64_t off, char *out, size_t cap);

#endif /* KOFENG_CALLNAMES_H */
