/*
 * diag_vocab.h - the words a diagnose node is described in: the role an
 * argument plays at it, and how far a link to it was established (defined by
 * libgenome, which walks the diagnose tree and records both for each link; the
 * engine re-exports it from <kofmod/kofdiagtree.h>, where a diagnose has always
 * found it).
 */
#ifndef KGENOME_DIAG_VOCAB_H
#define KGENOME_DIAG_VOCAB_H

/*
 * WHICH INPUT OF THE CHILD CAME FROM THE PARENT.
 *
 * SEPARATE FROM KOF_FLOW_ROLE_*, which answers a different question - which
 * argument decides what the CALL ITSELF means, like mmap's prot or socket's
 * domain. Sharing the name would put two meanings on one word in a file
 * where both are in scope.
 *
 * A role and not an argument index, because the index differs between the
 * syscall and the import that mean the same thing, and a diagnose must not
 * have to know which route satisfied it.
 */
enum kgenome_diag_role {
	KGENOME_DIAG_ROLE_NONE = 0,  /* the anchor: nothing fed it            */
	KGENOME_DIAG_ROLE_BUFFER,    /* read/write/recv: the memory written   */
	KGENOME_DIAG_ROLE_TARGET,    /* an indirect jump or call: where it goes */
	KGENOME_DIAG_ROLE_FD,        /* read/connect/close: the descriptor    */
	KGENOME_DIAG_ROLE_PATH,      /* open/exec: the name                   */
	/*
	 * THE MEMORY READ FROM, as against BUFFER which is the memory
	 * WRITTEN. A call with one of each needs both words.
	 *
	 * copy_to_user(to, from, n) is the case, and it is not a corner one:
	 * a hooked getdents reads a directory listing in, edits it, and
	 * writes it back, so the pair shares TWO objects - the kernel buffer
	 * it edits in and the userspace buffer the caller asked it to fill.
	 * With one word for both, the two relations collapse: kgenome_diag_note_in
	 * refuses the second as a repeat of the first, and the one it keeps is
	 * whichever came first.
	 *
	 * That refusal is right for a LOOP - the same site reached twice has
	 * not found a second relation - and it was hiding this. A role has to
	 * be precise enough that no call has two inputs wearing one.
	 */
	KGENOME_DIAG_ROLE_SOURCE,
	/*
	 * THE VALUE A CALL IS APPLIED TO, in a script. A decode takes bytes and gives bytes; an eval takes text and runs it. Neither
	 * has a descriptor or a path or a buffer in memory - the argument IS the value - so no other word fits, and a script's
	 * diagnose says "the decode's result was what the eval ran" with this one. Appended: a role is a field of every pack
	 * record and a renumbering breaks every diagnose.
	 */
	KGENOME_DIAG_ROLE_VALUE,
	/*
	 * THE NUMBER OF A SYSTEM CALL: the register that chose which call it is. A producer linked here is a node whose RESULT the number is
	 * (msfvenom's cleartext stager leaves connect's zero in rax and its next `syscall` is `read` because of it). The lineage stage follows
	 * it as it follows a descriptor (diag_lineage_solve.c, site_take); the node's class of it is kgenome_diag_hit.nr. It is never in a
	 * node's four-input view (kgenome_diag_hit.in[]): no pack names it, so the graph block does not carry it (kofdiag.c). Appended, as
	 * VALUE was: a renumbering breaks every diagnose.
	 */
	KGENOME_DIAG_ROLE_NUMBER,
	KGENOME_DIAG_ROLE_COUNT
};

/*
 * HOW FAR A LINK WAS ESTABLISHED. Three answers and not two.
 *
 * `BROKEN` and `UNKNOWN` must not be folded together. One says the value
 * demonstrably came from somewhere else - the diagnose really does not
 * match. The other says the model lost the value, through arithmetic it
 * does not follow or a round trip through memory it cannot see. Folded,
 * an author who can make the engine lose track has made themselves
 * innocent; kept apart, the weak answer can be weighed by the layer above.
 */
enum kgenome_diag_link {
	KGENOME_DIAG_LINK_PROVEN = 0,
	KGENOME_DIAG_LINK_BROKEN,
	KGENOME_DIAG_LINK_UNKNOWN,
	/*
	 * TRUE FOR AT LEAST ONE CALL, NOT SHOWN FOR ALL. A script's link made through a function the text defines: the producers of every call of the
	 * function reach what its parameter feeds (a summary is the union over the call sites, and no control flow is read). Appended: a value
	 * of this byte is read by no matcher and written to no pack, so a new one moves nothing.
	 */
	KGENOME_DIAG_LINK_MAY
};

/*
 * WHERE A SYSTEM CALL'S NUMBER CAME FROM (kgenome_diag_hit.nr), decided by the lineage stage from what reaches the number at the site,
 * over every path. NONE: not a system call, or no stage read it. CONST: a constant on every path - the ordinary case. PARAM: what the
 * function's caller passed (a syscall wrapper). RESULT: the answer of an earlier node on some path - abnormal: the program chose the call
 * by what another call returned (msfvenom's cleartext stager leaves connect's zero in rax and its next `syscall` is `read` because of it),
 * and kgenome_diag_hit.nr_from names which node. UNKNOWN: none of these (arithmetic, memory the stage cannot name).
 *
 * THE NUMBER'S PRODUCERS ARE INPUTS OF THE NODE like any other (role KGENOME_DIAG_ROLE_NUMBER, kgenome_diag_in_at); the class is the fact
 * about them, and nr_from / nr_how / nr_n repeat the lead of them for a reader of the node alone.
 */
enum kgenome_diag_nr {
	KGENOME_DIAG_NR_NONE = 0,
	KGENOME_DIAG_NR_CONST,
	KGENOME_DIAG_NR_PARAM,
	KGENOME_DIAG_NR_RESULT,
	KGENOME_DIAG_NR_UNKNOWN
};

#endif /* KGENOME_DIAG_VOCAB_H */
