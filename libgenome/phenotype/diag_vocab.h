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
	KGENOME_DIAG_LINK_UNKNOWN
};

#endif /* KGENOME_DIAG_VOCAB_H */
