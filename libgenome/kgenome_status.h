#ifndef KGENOME_STATUS_H
#define KGENOME_STATUS_H

/*
 * kgenome_status.h - what a kgenome call says about the COMPLETENESS of its answer.
 *
 * kgenome has a status of its own for the reason kuncoat has (libuncoat/status.h):
 * what fails in a disassembler or an emulator is not what fails in a decompressor,
 * and one shared "error" word would make a caller read "the object is not a PE"
 * and "the walk stopped at its bound" as the same thing.
 *
 * THE RULE THIS ENUM EXISTS FOR (CLAUDE.md rule 4, and the owner's: "a cap hit is
 * 'cannot say', never 'none'"). A limit that fires does not make an answer wrong,
 * it makes it PARTIAL, and a partial answer that looks complete is how a
 * detection is lost without a trace: MAX_LOOP dropped 11806 loops and nothing said
 * so. So every limit in kgenome - every cap on a result and every cut-off on a
 * piece of work - sets one of the values below, and the answer a caller reads
 * carries it. A caller asking "is this capability absent" must read the status
 * first and answer "cannot say" for anything but KGENOME_OK.
 *
 *   KGENOME_OK           the answer is complete for this object
 *   KGENOME_TRUNCATED    a limit was reached: what is returned is true and partial
 *   KGENOME_OVER_BUDGET  the caller's budget (kgenome_budget) was exhausted: same
 *                        meaning, and the budget is what to raise
 *   KGENOME_BAD_INPUT    the object is not what the call needs (not a PE, no code)
 *   KGENOME_UNSUPPORTED  a format or architecture this lib has no analysis for
 *   KGENOME_NOMEM        an allocation failed: the answer is partial for a reason
 *                        that is not the object's
 *
 * THE ORDER IS SEVERITY, and kgenome_status_merge keeps the worse of two, which
 * is how a scan that ran six routines reports one status: the first routine's
 * "truncated" is not erased by the second's "ok".
 */

enum kgenome_status {
	KGENOME_OK = 0,
	KGENOME_TRUNCATED,
	KGENOME_OVER_BUDGET,
	KGENOME_BAD_INPUT,
	KGENOME_UNSUPPORTED,
	KGENOME_NOMEM
};

/* The worse of two statuses. Anything but OK beats OK; a later, more severe
 * status replaces an earlier one and an equal or milder one does not. */
static inline enum kgenome_status kgenome_status_merge(enum kgenome_status a,
						       enum kgenome_status b)
{
	return b > a ? b : a;
}

/* Did a limit cut the answer - the three statuses that say "true and partial".
 * BAD_INPUT and UNSUPPORTED are about the input and not about a bound. */
static inline int kgenome_status_is_cut(enum kgenome_status s)
{
	return s == KGENOME_TRUNCATED || s == KGENOME_OVER_BUDGET || s == KGENOME_NOMEM;
}

static inline const char *kgenome_status_name(enum kgenome_status s)
{
	switch (s) {
	case KGENOME_OK:          return "ok";
	case KGENOME_TRUNCATED:   return "truncated";
	case KGENOME_OVER_BUDGET: return "over-budget";
	case KGENOME_BAD_INPUT:   return "bad-input";
	case KGENOME_UNSUPPORTED: return "unsupported";
	case KGENOME_NOMEM:       return "nomem";
	}
	return "?";
}

/* Is the answer the whole answer. */
static inline int kgenome_status_complete(enum kgenome_status s)
{
	return s == KGENOME_OK;
}

#endif /* KGENOME_STATUS_H */
