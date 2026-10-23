/*
 * codenotes.h - what an object's code says about itself, as labels and comments a reader can put beside the disassembly.
 *
 * ONE ANALYSIS, ON REQUEST, OF THE WHOLE OBJECT: the lib reads the code once (kgenome_codemap: branches, calls, syscalls, who refers to what) and
 * this names what it found with what the engine knows - the function table and symbol block, the relocation table of a module, the syscall
 * vocabulary - and writes the result as a table keyed by file offset. A viewer draws the part it is showing; nothing is worked out when it draws, and
 * nothing here depends on what it shows. A scan does not build this: it costs a read of the whole code, and only a reader who asked for it pays.
 *
 * THREE KINDS OF NOTE, because they are drawn differently and must never be read as one another:
 *   FUNC     a function's name, where it starts: a named symbol, or `sub_<offset>` for an entry the code itself calls and no symbol names.
 *   LABEL    a place a jump lands that is not a function: `.L-<offset>`. A jump label is NOT a function name and never borrows one.
 *   COMMENT  what an instruction does: where a call or jump goes, that a jump goes backward (a loop's back edge is one, but a backward jump is not always a loop: that takes the flow graph), which syscall a syscall is.
 * A FUNC or LABEL text ends with `  ; xrefs: ...` - who refers to the place - and a viewer draws that part as a comment.
 */
#ifndef KOFENG_CODENOTES_H
#define KOFENG_CODENOTES_H

#include <stdint.h>

#include <kofmod/kofsig.h>
#include <genotype/image/funcs.h>

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
 * the analysis (possibly empty), 0 when there is no decoder for the object's architecture or memory was refused; `out` then owns nothing. Free it
 * with kof_codenotes_free.
 */
int kof_codenotes_build(const struct kof_obj_ctx *ctx, kof_buf data, const struct kgenome_func_set *funcs,
			const uint8_t *sym, uint32_t sym_n, unsigned bits, struct kof_codenotes *out);
void kof_codenotes_free(struct kof_codenotes *n);

/* The notes of the instruction at `at`: a pointer to the first and how many (0 and NULL for none). */
const struct kof_note *kof_codenotes_at(const struct kof_codenotes *n, uint64_t at, uint32_t *count);
static inline const char *kof_codenotes_text(const struct kof_codenotes *n, const struct kof_note *x)
{
	return n->pool + x->text;
}

#endif /* KOFENG_CODENOTES_H */
