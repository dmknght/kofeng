/*
 * fntab_pe_thunk.c - the import-stub strategy of the PE function table (fntab.h): `jmp [slot]`, the six bytes the linker puts in the code for every imported function a direct
 * `call` names (the call goes to the stub and the stub jumps through the import address table).
 *
 * WHY A KIND OF ITS OWN. A stub is a body that no author wrote and that is not a function to sign: left to the walk, a stub is a start (the calls to it) with no end, so its end
 * is the NEXT start - the next stub's, one after the other - and the last stub of a run swallows whatever follows. Here its body is the instruction itself: start and end exact by
 * decode (end_source INSN), kind THUNK, so the stubs of a run are six bytes each and nothing around them is eaten. The walk found them in its one decode (diag_wrapper_walk.c: an
 * indirect jump through a fixed slot, the slot an entry of the IAT when the image declares one, at a function start: after a ret, a jmp, padding); this reads that list and decodes
 * nothing. Starts of kind FUNC from the same address (a call target) are one entry in the merge (the sources add up).
 */
#include "diag_scan_private.h"
#include <genotype/image/fntab.h>

void kgenome_fntab_pe_thunk(const struct kgenome_diag_walk *walk, struct kgenome_fntab_list *out)
{
	struct kgenome_func f;
	const struct kgenome_diag_stub *t;
	uint32_t n, i;

	memset(&f, 0, sizeof f);
	t = kgenome_diag_walk_thunks(walk, &n);
	for (i = 0; i < n; i++) {
		if (!t[i].iat || !t[i].start)
			continue;
		f.off = t[i].at;
		f.len = t[i].len;
		f.kind = KGENOME_FN_THUNK;
		f.source = KGENOME_FN_S_WALK;
		f.end_source = KGENOME_FN_E_INSN;
		if (!kgenome_fntab_list_add(out, &f))
			return;
	}
}
