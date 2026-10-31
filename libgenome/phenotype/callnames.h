/*
 * callnames.h - WHAT A CALL TO AN IMPORT IS CALLED: the places in an object's code that stand for an imported function, as a table a viewer or a
 * report can ask. Built ONCE per object, on request, by one read of the code (the shared reader, kgenome_diag_code_run).
 *
 * WHAT IS IN IT. One entry per instruction that is `jmp [slot]` or `call [slot]` where `slot` is the address the loader fills with an import
 * (ELF: a GOT slot of a RELA JUMP_SLOT / GLOB_DAT relocation, kgenome_elf_imports; PE: an IAT slot, kgenome_pe_imptab_build), keyed by that instruction's
 * FILE OFFSET:
 *   KGENOME_CALLNAME_STUB   a `jmp [slot]` - the PLT entry of an ELF (`.plt`, the IBT `.plt.sec` whose stub starts at its `endbr64`, `.plt.got`) or the
 *                           import thunk of a PE. A direct `call`/`jmp` that lands on `off` goes to the import. The `endbr64` before an IBT stub
 *                           is its own entry: a call lands there.
 *   KGENOME_CALLNAME_SLOT   a `call [slot]` (what -fno-plt and every x64 PE compile to) or a `jmp [slot]` in the program's own code (a tail call):
 *                           the instruction itself goes to the import.
 * A viewer asks `kgenome_callnames_at` with the branch's target when it is direct and with the instruction's own offset when it is indirect.
 *
 * NAMES ARE NOT COPIED. `nameoff` is where the name is in the object's bytes (0 for a PE import by ordinal, which has `ordinal` instead) and `dll` indexes
 * the PE's library names. How a name is SPELLED (`rand@plt`, `kernel32.dll!Sleep`) is the engine's (kof_callnames_name): the lib holds positions.
 *
 * NOT CAPPED. The table is as long as the object's imports and call sites make it; what bounds it is the object's own size, and the ledger the caller passes
 * (a refusal is KGENOME_OVER_BUDGET, never a silent cut). STATUS: KGENOME_OK complete; KGENOME_TRUNCATED a name was cut at KGENOME_SYMNAME_MAX or the PE thunk
 * budget ran out; KGENOME_OVER_BUDGET / KGENOME_NOMEM short for want of memory; KGENOME_UNSUPPORTED the architecture or format has no resolver here;
 * KGENOME_BAD_INPUT the object has no parsed header to read imports from.
 *
 * SCOPE LIMIT, named: ARM and AArch64 PLT stubs (`adrp x16, GOT; ldr x17, [x16, #off]; add; br x17`) are not resolved. The slot is a constant the register
 * model of the cursor (kgenome_cell_reg) already holds after the `adrp`; the next algorithm is to read each stub with that model and take the slot from the
 * `ldr`'s base register + displacement. MIPS and Thumb likewise. They answer KGENOME_UNSUPPORTED, not an empty table.
 */
#ifndef KGENOME_CALLNAMES_H
#define KGENOME_CALLNAMES_H

#include <stdint.h>

#include "../kgenome_budget.h"
#include "../kgenome_status.h"
#include "../genotype/image/obj.h"
#include <kofcore.h>

enum kgenome_callname_kind {
	KGENOME_CALLNAME_STUB = 1,
	KGENOME_CALLNAME_SLOT
};

#define KGENOME_CALLNAME_DLLLEN 64u

struct kgenome_callname {
	uint64_t off;           /* the instruction's file offset (the sort key) */
	uint64_t nameoff;       /* the import's name in the object's bytes; 0 = by ordinal */
	uint32_t ordinal;       /* a PE import by ordinal */
	uint32_t dll;           /* PE: index into kgenome_callnames.dll */
	uint8_t  kind;          /* enum kgenome_callname_kind */
	uint8_t  _pad[7];
};

struct kgenome_callnames {
	struct kgenome_callname *v;     /* ordered by `off`, one per offset */
	uint32_t n, cap;
	char (*dll)[KGENOME_CALLNAME_DLLLEN];   /* PE library names, once per library */
	uint32_t n_dll;
	enum kgenome_status status;
	uint8_t  format;        /* enum kgenome_fmt of the object it was built for */
	uint64_t bytes;         /* what the table holds now, as charged to the ledger */
	uint64_t insns;         /* instructions the one read of the code decoded: the work this table cost */
};

struct kgenome_callnames_req {
	const struct kgenome_obj *obj;
	kof_buf                   file;         /* the object's bytes */
	struct kgenome_ledger    *led;          /* the caller's account; NULL = none */
};

/* Does this lib resolve call names for the object: an ELF or PE of x86 or x86-64 with a parsed header. */
int kgenome_callnames_applicable(const struct kgenome_obj *obj);

/*
 * Build the table. Returns 1 when `out` holds an answer (possibly empty: an object that imports nothing), 0 when the object is not one the lib resolves
 * (`out->status` says why). Free with kgenome_callnames_free, which gives the ledger back what was charged.
 */
int kgenome_callnames_build(const struct kgenome_callnames_req *rq, struct kgenome_callnames *out);
void kgenome_callnames_free(struct kgenome_callnames *t, struct kgenome_ledger *led);

/* The entry at file offset `off`, or NULL. */
const struct kgenome_callname *kgenome_callnames_at(const struct kgenome_callnames *t, uint64_t off);

#endif /* KGENOME_CALLNAMES_H */
