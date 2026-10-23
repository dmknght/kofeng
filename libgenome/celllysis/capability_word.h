/*
 * celllysis/capability_word.h - THE SHAPE OF THE CAPABILITY WORD: context, group, action.
 *
 * A capability is one 16-bit value of three fields; this is the field layout (enum
 * kgenome_cap_ctx, kgenome_cap_group, the action numbers of each group), the macros that
 * build and take a value apart (KGENOME_NUCLEO_MK, _GROUP, _ACT, _DENSE, _VALID) and the
 * ceiling on groups. The words themselves are capability_ids.h; the per-node flags are
 * capability_flags.h; <celllysis/capability.h> is the umbrella of the three.
 *
 */
#ifndef KGENOME_CAPABILITY_WORD_H
#define KGENOME_CAPABILITY_WORD_H

#include <stdint.h>

/*
 * WHAT A NODE MEANS, and the vocabulary is deliberately NOT syscall numbers.
 *
 * The middle of a stager is identical on both platforms - allocate something
 * executable, read from the network, jump into it - and only the way of asking
 * differs: a syscall number on Linux, an import on Windows, a hashed export in
 * Windows shellcode. A rule written against these words survives that
 * difference; one written against 42 does not. Same argument kofevt makes for
 * its verbs, one layer down.
 *
 * Kept under 32 so a set of them is one word - see the per-function capability mask, which
 * is the prefilter that decides whether two regions are worth comparing at all.
 */
/*
 * THE CAPABILITY, AS (CONTEXT, GROUP, ACTION) AND NOT AS ONE NUMBER.
 *
 * It used to be a flat enum and the mask was `1ull << cap`, so the
 * vocabulary could hold sixty-four words and the sixty-fifth would have been
 * undefined behaviour. The list had reached fifty-three with eleven left,
 * and the splits this vocabulary still owes - proc-exec into five words,
 * proc-mem into three, cred-set into four - need nineteen. The ceiling was
 * about to decide the taxonomy, which is the wrong way round.
 *
 * So the number carries three fields and THE MASK IS OVER THE GROUP. There
 * are sixteen groups and there will not be sixty-four, while a group may
 * hold as many actions as the thing really has. Every place that asked `does
 * this function have capability X` was asking about a group - see
 * the three sites that read it (the capability tests and the object probe mask).
 *
 * AND THE CONTEXT, which is the third field: the same action done from a
 * kernel module is not the same evidence. `vfs_read` and `read` are one
 * action in two worlds, so they are one (group, action) and differ in the
 * context - which is what puts `kmodule-` in front of the name rather than a
 * second copy of every action inside a kernel group.
 */
enum kgenome_cap_ctx { KGENOME_CCTX_USER = 0, KGENOME_CCTX_KERNEL = 1 };

enum kgenome_cap_group {
	KGENOME_CG_BARE = 0,
	KGENOME_CG_MEM,
	KGENOME_CG_FILE,
	KGENOME_CG_NET,
	KGENOME_CG_PIPE,
	KGENOME_CG_PROC,
	KGENOME_CG_LIB,
	KGENOME_CG_REG,
	KGENOME_CG_CRED,
	KGENOME_CG_KMOD,
	KGENOME_CG_BPF,
	KGENOME_CG_CRYPTO,
	KGENOME_CG_INPUT,
	KGENOME_CG_NS,
	KGENOME_CG_SERVICE,
	KGENOME_CG_DATA,
	/*
	 * READ AND WRITE THROUGH A DESCRIPTOR, SOURCE NOT DETERMINED.
	 *
	 * `read(2)` was in KGENOME_CG_FILE and called file-read. It is not a file
	 * operation: it takes a descriptor, and what the descriptor IS - a
	 * file, a socket, a pipe, a terminal - the syscall number cannot say.
	 * MEASURED on msfvenom's x86-64 stager, which reads its second stage
	 * from a socket: the engine reported file-read while holding, as a
	 * proven link, the fact that the descriptor came from socket().
	 *
	 * So the generic calls move here and the word says only what is known:
	 * bytes moved through a descriptor, into or out of a buffer.
	 *
	 * AND IT IS NOT RENAMED WHEN THE DESCRIPTOR IS IDENTIFIED. That was
	 * tried: a link proving the fd came from socket() rewrote the node to
	 * net-recv. It is wrong twice over.
	 *
	 * The LINK ALREADY SAYS IT. An fd-role link pointing at a net-open IS
	 * the statement "this descriptor is a socket"; putting it on the node
	 * as well is one fact with two carriers, and the two can disagree.
	 *
	 * And the node has MORE THAN ONE LINK. meterpreter's call is
	 * read(socket-fd, alloc-exec-buffer, n) - bytes moving from a socket
	 * into executable memory. Naming the node after its fd throws the
	 * buffer link's meaning away, and no single word carries both: the
	 * fact is the pair of links. MEASURED, the rename also broke every
	 * rule that named the generic word and forced a specialisation
	 * mechanism into the matcher to undo its own damage.
	 *
	 * The calls that really are file operations because they take a FILE
	 * and not a descriptor - vfs_read, kernel_read, ReadFile, ZwReadFile -
	 * stay where they were.
	 *
	 * ADDED AT THE END. The groups are part of every capability id and a
	 * renumbering breaks every rule that named one.
	 */
	KGENOME_CG_IO,
	KGENOME_CG_COUNT
};

/* The action, numbered inside its own group and nowhere else. */
enum { KGENOME_CA_BARE_SLEEP = 1, KGENOME_CA_BARE_ANTI_DEBUG };
enum { KGENOME_CA_MEM_ALLOC = 1, KGENOME_CA_MEM_ALLOC_EXEC, KGENOME_CA_MEM_ALLOC_HEAP,
       KGENOME_CA_MEM_EXEC, KGENOME_CA_MEM_MEMFD_CREATE,
       /*
        * IN THE GROUP'S OWN NUMBERING, which is not decoration: an action
        * is one of KGENOME_NUCLEO_ACT_MAX per group, because KGENOME_NUCLEO_DENSE maps
        * (group, action) onto a flat slot with that stride. These two were
        * added at 90 and 91 in an enum of their own, which put them past
        * the stride - so KGENOME_NUCLEO_VALID answered NO for both, and that is
        * not a cosmetic refusal: diag_cap_of walks the capability space
        * asking which values are valid, so a diagnose naming
        * "mem-action-write" was rejected as "not a capability", and
        * tests/lib/genome/diag_roles.c skipped them for the same reason.
        */
       KGENOME_CA_MEM_ACTION_READ, KGENOME_CA_MEM_ACTION_WRITE };
enum { KGENOME_CA_FILE_OPEN = 1, KGENOME_CA_FILE_READ, KGENOME_CA_FILE_WRITE, KGENOME_CA_FILE_DELETE, KGENOME_CA_FILE_RENAME, KGENOME_CA_FILE_PERM_SET, KGENOME_CA_FILE_TIMESTAMP_SET };
enum { KGENOME_CA_NET_OPEN = 1, KGENOME_CA_NET_OPEN_RAW, KGENOME_CA_NET_CONNECT, KGENOME_CA_NET_BIND, KGENOME_CA_NET_LISTEN, KGENOME_CA_NET_ACCEPT, KGENOME_CA_NET_SEND, KGENOME_CA_NET_RECV, KGENOME_CA_NET_GETADDR, KGENOME_CA_NET_ADDR,
       /* HTTP is a layer above, not a spelling of the same thing - see
	* KGENOME_NUCLEO_HTTP_SEND. Appended, because renumbering breaks every rule
	* that named one of the words before it. */
       KGENOME_CA_NET_HTTP_OPEN, KGENOME_CA_NET_HTTP_CONNECT, KGENOME_CA_NET_HTTP_SEND,
       KGENOME_CA_NET_HTTP_RECV, KGENOME_CA_NET_HTTP_FETCH,
       /* The sender builds its own IP header - setsockopt(IP_HDRINCL). Appended
	* with the rest: renumbering breaks every rule that named a word. */
       KGENOME_CA_NET_HDRINCL };
enum { KGENOME_CA_PIPE_CREATE = 1, KGENOME_CA_PIPE_NAMED_CREATE };
enum { KGENOME_CA_PROC_START = 1, KGENOME_CA_PROC_FORK, KGENOME_CA_PROC_BACKGROUND, KGENOME_CA_PROC_ENUM, KGENOME_CA_PROC_OPEN, KGENOME_CA_PROC_MEM_ACCESS, KGENOME_CA_PROC_CONTROL, KGENOME_CA_PROC_THREAD_CREATE, KGENOME_CA_PROC_FD_REDIRECT, KGENOME_CA_PROC_SELF_NAME };
enum { KGENOME_CA_LIB_LOAD = 1, KGENOME_CA_LIB_API_RESOLVE, KGENOME_CA_LIB_NAME_HASH, KGENOME_CA_LIB_PEB_WALK, KGENOME_CA_LIB_CALL_REGISTER };
enum { KGENOME_CA_REG_OPEN = 1, KGENOME_CA_REG_SET };
enum { KGENOME_CA_CRED_MODIFY = 1, KGENOME_CA_CRED_PREPARE };
enum { KGENOME_CA_KMOD_LOAD = 1, KGENOME_CA_KMOD_HOOK, KGENOME_CA_KMOD_LIST_EDIT,
       KGENOME_CA_KMOD_CR_WRITE, KGENOME_CA_KMOD_KPROBE_REG,
       KGENOME_CA_KMOD_KPROBE_UNREG, KGENOME_CA_KMOD_COPY_FROM_USER,
       KGENOME_CA_KMOD_COPY_TO_USER, KGENOME_CA_KMOD_KSYM_LOOKUP,
       KGENOME_CA_KMOD_SYMBOL_GET };
enum { KGENOME_CA_CRYPTO_ANY = 1 };
enum { KGENOME_CA_INPUT_CAPTURE = 1,
       /* what a request brings in ($_GET, $_POST...): appended, a renumbering breaks every rule that named a word */
       KGENOME_CA_INPUT_REQUEST };
/* What a script does with data that no native program has a word for. Appended to a group that had no actions; the later words are
 * appended after the first two, never inserted: a renumbering breaks every rule that named a word. */
enum { KGENOME_CA_DATA_DECODE = 1, KGENOME_CA_DATA_EVAL, KGENOME_CA_DATA_CREATE, KGENOME_CA_DATA_CALL,
       KGENOME_CA_DATA_LOAD };
enum { KGENOME_CA_NS_CHANGE = 1 };
enum { KGENOME_CA_SERVICE_INSTALL = 1 };

/*
 * THE FIELDS: context in bits 13-15, group in bits 8-12, action in bits 0-7.
 *
 * The group field is FIVE bits and not four. KGENOME_CG_IO is the seventeenth group (16), and
 * a four-bit field carried it into the context bit: mem-read (0x1001) read back as context
 * KERNEL, group BARE, one dense slot with `sleep`. Every value that was ever built keeps its
 * number - they are all context USER and a group below 17 - so the context moved up instead
 * of the group being renumbered, and nothing a module or a pack holds changes.
 */
#define KGENOME_NUCLEO_MK(ctx, grp, act) \
	((uint16_t)(((uint16_t)(ctx) << 13) | ((uint16_t)(grp) << 8) | (uint16_t)(act)))
#define KGENOME_NUCLEO_CTX(c)   ((unsigned)(((c) >> 13) & 0x7u))
#define KGENOME_NUCLEO_GROUP(c) ((unsigned)(((c) >> 8) & 0x1fu))
#define KGENOME_NUCLEO_ACT(c)   ((unsigned)((c) & 0xffu))


/*
 * AND THE CEILING, which is a bitmask and was two words away without saying so.
 *
 * A function's capabilities are kept as `1ull << cap` in the per-function mask,
 * in the object probe mask and in kof_diag_mask. While that shift was `1u`
 * the vocabulary could hold thirty-two words and the thirty-third would have
 * been UNDEFINED BEHAVIOUR - not a wrong answer, not a build error, just a
 * shift the compiler is free to turn into anything. The list above had reached
 * thirty.
 *
 * The shift is 64-bit now, and this says so out loud, because the failure it
 * guards against is one nobody would see: adding a word is a three-line
 * change in three tables and nothing about those three lines suggests a limit.
 */
/*
 * THE CEILING, NOW OVER GROUPS AND NOT OVER WORDS.
 *
 * `1ull << cap` is gone: the mask is `1ull << KGENOME_NUCLEO_GROUP(cap)` and there
 * are sixteen groups, so the vocabulary can grow a word whenever the thing
 * it names is real. What is bounded is the number of ACTIONS inside one
 * group, because the dense index below multiplies by a fixed stride - and
 * that bound is checked here rather than discovered by a profile entry
 * landing on its neighbour.
 */
typedef char kgenome_cap_groups_fit[(KGENOME_CG_COUNT <= 32) ? 1 : -1];     /* the five-bit group field */

/*
 * A DENSE SLOT PER CAPABILITY, for the arrays that cannot be sparse.
 *
 * The value carries three fields so it is not a small number any more, and
 * the usage profile indexes two arrays by capability. This maps it to a dense
 * slot. The stride is the real limit on actions per group; the assert above
 * does not catch that, so every table that fills a group is written against
 * it and KGENOME_NUCLEO_ACT_MAX says so out loud.
 */
#define KGENOME_NUCLEO_ACT_MAX   32u        /* net-hdrincl is action 16 of its group: 16 was one short */
#define KGENOME_NUCLEO_DENSE(c)  ((unsigned)(KGENOME_NUCLEO_GROUP(c) * KGENOME_NUCLEO_ACT_MAX \
			   + KGENOME_NUCLEO_ACT(c)))
/* A value that could have come from KGENOME_NUCLEO_MK and nothing else. Replaces
 * `cap < KOF_NUCLEO_COUNT`, which stopped meaning anything when the values
 * stopped being consecutive. */
#define KGENOME_NUCLEO_VALID(c) ((c) && KGENOME_NUCLEO_GROUP(c) < KGENOME_CG_COUNT && \
			  KGENOME_NUCLEO_ACT(c) && KGENOME_NUCLEO_ACT(c) < KGENOME_NUCLEO_ACT_MAX)

#endif /* KGENOME_CAPABILITY_WORD_H */
