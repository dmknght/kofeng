/*
 * codenotes.h - what an object's code says about itself, as labels and comments a reader can put beside the disassembly.
 *
 * ONE ANALYSIS, ON REQUEST, OF THE WHOLE OBJECT: the lib reads the code once (kgenome_codemap: branches, calls, syscalls, who refers to what) and
 * this names what it found with what the engine knows - the function table and symbol block, the relocation table of a module, the syscall
 * vocabulary - and writes the result as a table keyed by file offset. A viewer draws the part it is showing; nothing is worked out when it draws, and
 * nothing here depends on what it shows. A scan does not build this: it costs a read of the whole code, and only a reader who asked for it pays.
 *
 * THREE KINDS OF NOTE, because they are drawn differently and must never be read as one another:
 *   FUNC     a function's name, where it starts: a function of the function table, by its symbol or `fcn_<offset>` (kof_func_name) when no symbol names it. A call target the table does not
 *            hold is not a function (the table is the one answer).
 *   LABEL    a place something branches to that is not a function of the table: `.L-<offset>` for a jump landing, `fcn_<offset>` for a call target the table lacks (spelled as the call that reaches
 *            it spells it). A jump label is NOT a function name and never borrows one.
 *   COMMENT  what an instruction does: where a call or jump goes, that a jump goes backward (a loop's back edge is one, but a backward jump is not always a loop: that takes the flow graph), which syscall a syscall is.
 * A FUNC or LABEL text ends with `  ; xrefs: ...` - who refers to the place - and a viewer draws that part as a comment.
 */
#ifndef KOFENG_CODENOTES_H
#define KOFENG_CODENOTES_H

#include <stdint.h>

#include <kofmod/kofsig.h>
#include <genotype/image/funcs.h>
#include <phenotype/callnames.h>

enum kof_note_kind {
	KOF_NOTE_FUNC = 1,
	KOF_NOTE_LABEL,
	KOF_NOTE_COMMENT
};

struct kof_note {
	uint64_t at;            /* the file offset of the instruction the note belongs to */
	uint32_t text;          /* offset of its NUL-ended text in the pool */
	uint8_t  kind;          /* enum kof_note_kind */
};

struct kof_codenotes {
	struct kof_note *v;     /* ordered by `at`, labels (FUNC, LABEL) before the COMMENT of the same instruction */
	uint32_t n;
	char *pool;
	uint32_t pool_n;
	/* KGENOME_OK, or KGENOME_NOMEM: short for want of memory, not for want of code. */
	enum kgenome_status status;
};

/*
 * Analyse `data` (the object's bytes, `ctx` its context). `funcs` and `sym`/`sym_n` are the object's function table and symbol block as the caller
 * holds them. `bits` is 32 or 64, the width to read an object that does not say (a raw blob); 0 leaves the object's own. Returns 1 when `out` holds
 * the analysis (possibly empty), 0 when there is no decoder for the object's architecture or memory was refused; `out` then owns nothing. `names`, when not NULL, is the object's call-name table (callnames.h): a call or
 * jump that lands on a PLT stub or PE thunk, or goes through an import slot, is then named `rand@plt` instead of `fcn_<offset>`. Free it
 * with kof_codenotes_free.
 */
/*
 * THE REQUEST: the same inputs, with two the caller may hold and the analysis would otherwise make again. `wk` is the object's walk (libgenome/phenotype: its trace is the decode of
 * the code, so the codemap READS it and decodes nothing); `relocs` the object's CODE relocation table as the engine holds it (NULL: read from the object). Both NULL is what
 * kof_codenotes_build does. The product is examine-only: nothing on the scan path calls it.
 */
struct kgenome_diag_walk;
struct kgenome_elf_relocs;
struct kof_codenotes_req {
	const struct kof_obj_ctx *ctx;
	kof_buf data;
	const struct kgenome_func_set *funcs;
	const uint8_t *sym;
	uint32_t sym_n;
	unsigned bits;
	const struct kgenome_callnames *names;
	struct kgenome_diag_walk *wk;
	const struct kgenome_elf_relocs *relocs;
};
int kof_codenotes_make(const struct kof_codenotes_req *rq, struct kof_codenotes *out);
/* The positional form kofexamine calls (parked): kof_codenotes_make with no walk and no relocations of the caller's. */
int kof_codenotes_build(const struct kof_obj_ctx *ctx, kof_buf data, const struct kgenome_func_set *funcs,
			const uint8_t *sym, uint32_t sym_n, unsigned bits, const struct kgenome_callnames *names,
			struct kof_codenotes *out);
void kof_codenotes_free(struct kof_codenotes *n);

/* The notes of the instruction at `at`: a pointer to the first and how many (0 and NULL for none). */
const struct kof_note *kof_codenotes_at(const struct kof_codenotes *n, uint64_t at, uint32_t *count);
static inline const char *kof_codenotes_text(const struct kof_codenotes *n, const struct kof_note *x)
{
	return n->pool + x->text;
}

#endif /* KOFENG_CODENOTES_H */
