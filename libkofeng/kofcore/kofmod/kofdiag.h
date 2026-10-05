/*
 * kofmod/kofdiag.h - A DIAGNOSE: what a program does, as a tree of nucleo
 * groups and the proven links between them.
 *
 * A diagnose NAMES NO FAMILY AND CARRIES NO VERDICT. It says "a region was
 * allocated writable and executable in one call, something filled it, and
 * control went into it" and stops there. Whether that is a Metasploit
 * stager, a beacon or a self-unpacking installer is a question for a
 * signature, which reads the diagnose result as a fact - see kof_diag.
 *
 * WHY SEPARATE FROM A SIGNATURE AT ALL. Two reasons, and both are about
 * what changes when:
 *
 *   - BEHAVIOUR IS SLOW. The shape above has been the same since the first
 *     runtime packer. A family name changes weekly. Keeping them in one
 *     file means the slow thing is rewritten every time the fast thing is.
 *   - ONE SHAPE, MANY FAMILIES. Embedding the shape in each family's rule
 *     is N copies of one piece of knowledge, and the copy that is not
 *     updated is the one that stops matching.
 *
 * SO IT IS A TREE, AND THE TREE IS THE RELATION. There are no edge records.
 * A node names its parent and says WHICH OF ITS OWN INPUTS came from that
 * parent - see `role`. Three fields carry what a general edge table would.
 *
 * THE TREE IS A PROVENANCE TREE AND NOT A SEQUENCE, which is the one thing
 * about it that reads wrong at first. In
 *
 *     p = mmap(RWX);  read(fd, p, n);  jmp p;
 *
 * `jmp` is NOT a child of `read` although it runs after it. Both take their
 * value from `mmap`, so both are children of `mmap`. That is what makes an
 * inserted node harmless: a `sleep` between the two is simply a node
 * nothing is matched against, and MEASURED - msfvenom's x86-64 stager has
 * exactly that sleep and matches with it there.
 *
 * WHAT IS DELIBERATELY ABSENT, because each was tried and cost more than it
 * bought:
 *
 *   - ORDER. Static order is LAYOUT order, not execution order - measured
 *     on a Watchbog sample where the walk read fork, wait, exec while the
 *     program runs fork, exec, wait: the compiler lays the parent's arm
 *     before the child's. Proving real order needs dominance, which needs a
 *     control-flow graph, which this does not build.
 *   - DISTANCE. A count of instructions between two nodes is the one part
 *     of a rule an author can evade by inserting one instruction.
 *   - A JOIN. Two trees sharing a node is not expressible here and is not
 *     meant to be: that is verdict logic and lives in a signature, over the
 *     bindings a match returns - see kof_diag_share.
 */

#ifndef KOFMOD_KOFDIAG_H
#define KOFMOD_KOFDIAG_H

#include <stdint.h>

#include "kofcap.h"

/*
 * WHICH ANALYSIS ROUTINE CAN SATISFY THIS DIAGNOSE, as a set.
 *
 * The two differ by a whole order of cost, so the engine must know which to
 * run before it runs anything:
 *
 *   SYMBOL   read the imports and compare names. NOT ONE INSTRUCTION is
 *            decoded.
 *   SYSCALL  a syscall is not in any symbol table. The code has to be
 *            scanned for the instruction, then decoded, then the number
 *            resolved out of a register.
 *
 * NOT DERIVABLE from the capabilities alone, which is why it is declared.
 * KOF_CAP_ALLOC_EXEC is reachable BOTH ways - `mmap` on a static ELF,
 * `VirtualAlloc` on a PE - while a diagnose about LoadLibrary followed by
 * GetProcAddress has only the symbol route and one about raw shellcode has
 * only the syscall route. Declaring it both bounds the work and says what
 * the diagnose is about.
 */
#define KOF_DIAG_VIA_SYSCALL (1u << 0)
#define KOF_DIAG_VIA_SYMBOL  (1u << 1)

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
enum kof_diag_role {
	KOF_DIAG_ROLE_NONE = 0,  /* the anchor: nothing fed it            */
	KOF_DIAG_ROLE_BUFFER,    /* read/write/recv: the memory written   */
	KOF_DIAG_ROLE_TARGET,    /* an indirect jump or call: where it goes */
	KOF_DIAG_ROLE_FD,        /* read/connect/close: the descriptor    */
	KOF_DIAG_ROLE_PATH,      /* open/exec: the name                   */
	/*
	 * THE MEMORY READ FROM, as against BUFFER which is the memory
	 * WRITTEN. A call with one of each needs both words.
	 *
	 * copy_to_user(to, from, n) is the case, and it is not a corner one:
	 * a hooked getdents reads a directory listing in, edits it, and
	 * writes it back, so the pair shares TWO objects - the kernel buffer
	 * it edits in and the userspace buffer the caller asked it to fill.
	 * With one word for both, the two relations collapse: kof_diag_note_in
	 * refuses the second as a repeat of the first, and the one it keeps is
	 * whichever came first.
	 *
	 * That refusal is right for a LOOP - the same site reached twice has
	 * not found a second relation - and it was hiding this. A role has to
	 * be precise enough that no call has two inputs wearing one.
	 */
	KOF_DIAG_ROLE_SOURCE,
	KOF_DIAG_ROLE_COUNT
};

/*
 * THE `parent` OF THE ROOT. One tree, one root, and the root is the node
 * the engine starts from - see the note on the anchor below.
 *
 * NOT CALLED KOF_DIAG_ANCHOR, although that is what it marks: the word is
 * already the authoring macro a few screens down, and two meanings on one
 * name in one header is a compile error on the good day and a wrong value
 * on the bad one.
 */
#define KOF_DIAG_NO_PARENT 0xffu

/* Bits in kof_diag_node.bits. */
#define KOF_DIAG_B_TOUCH (1u << 0)

/*
 * WHICH KIND OF EDGE THE DIAGNOSE WILL ACCEPT - see enum kof_diag_kind.
 *
 * NEITHER BIT SET MEANS EITHER, and that is the default on purpose: most
 * relations are provenance, a diagnose that does not care should not have to
 * say so, and every pack built before these bits existed carries zero here
 * and goes on meaning what it meant.
 *
 * SAYING IT MATTERS WHERE THE ORDER IS THE BEHAVIOUR. A module that fills a
 * buffer from userspace and writes one back has two edges to the allocation
 * and both are provenance; what makes it a hooked syscall rather than an
 * ioctl handler is that the second copy holds the SAME object the first one
 * filled. That is the shared edge, and a diagnose that cannot demand it
 * cannot tell the two apart.
 */
#define KOF_DIAG_B_PRODUCED (1u << 1)
#define KOF_DIAG_B_SHARED   (1u << 2)

/*
 * ONE NODE. Eight bytes and then its attributes.
 *
 * `cap` IS A NUCLEO GROUP ID AND NEVER A SYSCALL NUMBER OR A NAME. That is
 * the single most important property of this record:
 *
 *   - a rule written against `proc-start` matches execve on Linux and
 *     CreateProcess on Windows, because the group is what both resolve to;
 *   - adding an alias to the vocabulary - __GI_dup2, NtAllocateVirtualMemory
 *     - makes every existing rule see it, with no rebuild of the rule.
 *
 * Store the number or the name instead and both properties are lost. The
 * engine expands the group through nucleo for the object's format and
 * architecture, and THAT is what it looks for.
 *
 * SO THE GROUP IDS MUST BE FROZEN. Adding a word to a group is free;
 * renumbering a group breaks every rule that named it. Same discipline the
 * SIM_IT ids and the engine ids are held to.
 */
struct kof_diag_node {
	uint16_t cap;            /* enum kof_flow_cap - a GROUP, see above  */
	uint16_t flags;          /* KOF_FLOWF_* the node must carry         */
	uint8_t  parent;         /* index, or KOF_DIAG_NO_PARENT               */
	uint8_t  role;           /* enum kof_diag_role - which input        */
	uint8_t  bits;           /* KOF_DIAG_B_*                            */
	uint8_t  attr_len;       /* bytes of attribute following            */
	/* attr[attr_len] follows, see the note on attributes below */
};

/*
 * WHY THE ATTRIBUTE RUN CARRIES ITS OWN LENGTH rather than being a fixed
 * struct: so a pack built today still reads when a later build adds an
 * attribute kind. The same reason dbcore.h gives for keeping a plague
 * block's hashes in a second section rather than inside the block.
 *
 * WHAT BELONGS IN IT, and the line is the one the vocabulary already draws
 * between what the SYSTEM fixes and what the AUTHOR chose:
 *
 *   in   the CLASS of an argument - a path under a system directory, an
 *        executed program that is a shell. The class survives a variant
 *        renaming its dropper.
 *   out  the VALUE itself - "/usr/bin/mand", 185.10.68.100. That is
 *        evidence to report, not a thing to match on; matching it is
 *        pattern matching with extra steps.
 */

/*
 * THE ANCHOR MUST BE RARE, and this is a property a diagnose is responsible
 * for rather than one the engine can fix.
 *
 * Matching starts by finding every node in the object that could be the
 * root, and descends from each. A root of KOF_CAP_ALLOC_EXEC costs one
 * descent - measured, zero clean binaries in 846 of /usr/bin allocate
 * writable-and-executable in one call. A root of KOF_CAP_READ would cost
 * one descent per read, and a single 1.1 MB sample here holds 447 indirect
 * calls.
 *
 * The build warns when a diagnose anchors on a common group.
 */

struct kof_diag {
	uint16_t              id;       /* assigned by the build            */
	uint8_t               via;      /* KOF_DIAG_VIA_*                   */
	uint8_t               n_node;
	const char           *name;     /* for a person, never matched on   */
	const struct kof_diag_node *node;
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
enum kof_diag_link {
	KOF_DIAG_LINK_PROVEN = 0,
	KOF_DIAG_LINK_BROKEN,
	KOF_DIAG_LINK_UNKNOWN
};

/*
 * ---- WRITING ONE -----------------------------------------------------------
 *
 * A diagnose source is read as TEXT by the build, exactly as a signature's
 * declarations are. The macros expand to nothing: what they do is make the
 * declaration legal C so an editor and a compiler both accept the file,
 * while the thing that reads them is ksigbuilder.
 *
 *     KOF_DIAG_NAME(rwx_exec);
 *     KOF_DIAG_VIA(KOF_DIAG_VIA_SYSCALL | KOF_DIAG_VIA_SYMBOL);
 *
 *     KOF_DIAG_ANCHOR(a, KOF_CAP_ALLOC_EXEC, KOF_FLOWF_WX);
 *     KOF_DIAG_FROM(r, a, KOF_CAP_READ,     KOF_DIAG_ROLE_BUFFER);
 *     KOF_DIAG_FROM(x, a, KOF_CAP_EXEC_REG, KOF_DIAG_ROLE_TARGET);
 *     KOF_DIAG_TOUCH(r);
 *
 * KOF_DIAG_FROM NAMES THE PARENT RATHER THAN NESTING, because C has no
 * shape that nests and still reads as a tree - and a parent written out is
 * a parent a reader can see without counting braces. `a` is the parent of
 * both, which is the provenance tree and not the order they run in.
 *
 * KOF_DIAG_TOUCH is the diagnose OFFERING a node as a join point. A
 * signature may ask to be bound to one - see kof_diag_share - and asking
 * for a node that was not offered is not an error: the build turns the bit
 * on, because the declaration is an invitation and not a fence. Asking for
 * a label that does not EXIST is an error, because that is a typo or a
 * node somebody deleted.
 */
#define KOF_DIAG_NAME(id)
#define KOF_DIAG_VIA(mask)
#define KOF_DIAG_ANCHOR(label, cap, flags)
/*
 * KOF_DIAG_FROM takes an OPTIONAL FIFTH ARGUMENT, a kind:
 *
 *     KOF_DIAG_FROM(t, f, KOF_CAP_COPY_TO_USER, KOF_DIAG_ROLE_SOURCE,
 *                   KOF_DIAG_B_SHARED);
 *
 * Left out, the edge may be either kind - which is what every diagnose
 * written before this meant and still means. The macro expands to nothing,
 * so both arities are legal C and ksigbuilder reads whichever is written.
 */
#define KOF_DIAG_FROM(...)
#define KOF_DIAG_TOUCH(label)

#endif /* KOFMOD_KOFDIAG_H */
