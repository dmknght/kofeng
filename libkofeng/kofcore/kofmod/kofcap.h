/*
 * kofmod/kofcap.h - THE CAPABILITY VOCABULARY, and the shapes made of it.
 *
 * WHY IT IS A MODULE HEADER AND NOT AN ENGINE ONE.
 *
 * A rule used to reach this vocabulary only through a reference chain the
 * generator wrote for it - the words were the engine's and a rule carried
 * numbers. The words are a rule's own now, so they have to be where a
 * researcher's file can see them.
 *
 * NO RULE NAMES ONE YET. The macros that spent them - kof_pth_has and
 * kof_pth_feeds - went with the chain matcher, because a sequence with
 * distances could not hold the shapes they were asked about. The vocabulary
 * is what was kept; what reads it is being built again.
 *
 * It is the gene vocabulary in ESET's sense of the word: the features a
 * sample is reduced to before anything is compared. What a profile made of
 * them looks like is the scanner's business; what they MEAN is here.
 *
 * NOTHING IN THIS FILE READS AN OBJECT. It is names and widths only, so it
 * costs a rule nothing to include and carries no dependency but <stdint.h>.
 */
#ifndef KOFMOD_KOFCAP_H
#define KOFMOD_KOFCAP_H

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
 * Kept under 32 so a set of them is one word - see kof_flow_func.mask, which
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
 * kof_flow_has and kof_obj_probe.cap_mask, the three sites that read it.
 *
 * AND THE CONTEXT, which is the third field: the same action done from a
 * kernel module is not the same evidence. `vfs_read` and `read` are one
 * action in two worlds, so they are one (group, action) and differ in the
 * context - which is what puts `kmodule-` in front of the name rather than a
 * second copy of every action inside a kernel group.
 */
enum kof_cap_ctx { KOF_CCTX_USER = 0, KOF_CCTX_KERNEL = 1 };

enum kof_cap_group {
	KOF_CG_BARE = 0,
	KOF_CG_MEM,
	KOF_CG_FILE,
	KOF_CG_NET,
	KOF_CG_PIPE,
	KOF_CG_PROC,
	KOF_CG_LIB,
	KOF_CG_REG,
	KOF_CG_CRED,
	KOF_CG_KMOD,
	KOF_CG_BPF,
	KOF_CG_CRYPTO,
	KOF_CG_INPUT,
	KOF_CG_NS,
	KOF_CG_SERVICE,
	KOF_CG_DATA,
	KOF_CG_COUNT
};

/* The action, numbered inside its own group and nowhere else. */
enum { KOF_CA_BARE_SLEEP = 1, KOF_CA_BARE_ANTI_DEBUG };
enum { KOF_CA_MEM_ALLOC = 1, KOF_CA_MEM_ALLOC_EXEC, KOF_CA_MEM_ALLOC_HEAP, KOF_CA_MEM_EXEC, KOF_CA_MEM_MEMFD_CREATE };
enum { KOF_CA_FILE_OPEN = 1, KOF_CA_FILE_READ, KOF_CA_FILE_WRITE, KOF_CA_FILE_DELETE, KOF_CA_FILE_RENAME, KOF_CA_FILE_PERM_SET, KOF_CA_FILE_TIMESTAMP_SET };
enum { KOF_CA_NET_OPEN = 1, KOF_CA_NET_OPEN_RAW, KOF_CA_NET_CONNECT, KOF_CA_NET_BIND, KOF_CA_NET_LISTEN, KOF_CA_NET_ACCEPT, KOF_CA_NET_SEND, KOF_CA_NET_RECV, KOF_CA_NET_GETADDR, KOF_CA_NET_ADDR };
enum { KOF_CA_PIPE_CREATE = 1, KOF_CA_PIPE_NAMED_CREATE };
enum { KOF_CA_PROC_START = 1, KOF_CA_PROC_FORK, KOF_CA_PROC_BACKGROUND, KOF_CA_PROC_ENUM, KOF_CA_PROC_OPEN, KOF_CA_PROC_MEM_ACCESS, KOF_CA_PROC_CONTROL, KOF_CA_PROC_THREAD_CREATE, KOF_CA_PROC_FD_REDIRECT, KOF_CA_PROC_SELF_NAME };
enum { KOF_CA_LIB_LOAD = 1, KOF_CA_LIB_API_RESOLVE, KOF_CA_LIB_NAME_HASH, KOF_CA_LIB_PEB_WALK, KOF_CA_LIB_CALL_REGISTER };
enum { KOF_CA_REG_OPEN = 1, KOF_CA_REG_SET };
enum { KOF_CA_CRED_MODIFY = 1 };
enum { KOF_CA_KMOD_LOAD = 1, KOF_CA_KMOD_HOOK, KOF_CA_KMOD_LIST_EDIT, KOF_CA_KMOD_CR_WRITE };
enum { KOF_CA_CRYPTO_ANY = 1 };
enum { KOF_CA_INPUT_CAPTURE = 1 };
enum { KOF_CA_NS_CHANGE = 1 };
enum { KOF_CA_SERVICE_INSTALL = 1 };

#define KOF_CAP_MK(ctx, grp, act) \
	((uint16_t)(((uint16_t)(ctx) << 12) | ((uint16_t)(grp) << 8) | (uint16_t)(act)))
#define KOF_CAP_GROUP(c) ((unsigned)(((c) >> 8) & 0xfu))
#define KOF_CAP_ACT(c)   ((unsigned)((c) & 0xffu))
#define KOF_CAP_CTX(c)   ((unsigned)(((c) >> 12) & 0xfu))
/* The user-context capability this one is the kernel twin of, and back. */
#define KOF_CAP_AS_KERNEL(c) ((uint16_t)((c) | (KOF_CCTX_KERNEL << 12)))
#define KOF_CAP_BASE(c)      ((uint16_t)((c) & 0x0fffu))

enum kof_flow_cap {
	KOF_CAP_NONE = 0,
	KOF_CAP_ALLOC = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_MEM, KOF_CA_MEM_ALLOC),        /* a mapping, without execute permission */
	KOF_CAP_ALLOC_EXEC = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_MEM, KOF_CA_MEM_ALLOC_EXEC),   /* ... with it - mmap/mprotect and PROT_EXEC */
	KOF_CAP_NET_OPEN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_OPEN),     /* socket */
	KOF_CAP_NET_CONNECT = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_CONNECT),
	KOF_CAP_NET_ACCEPT = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_ACCEPT),
	/*
	 * TAKING AN ADDRESS ON THIS MACHINE - bind.
	 *
	 * SPLIT OUT OF KOF_CAP_NET_OPEN, which said `net-open` over
	 * `bind()` and meant nothing of the sort. Opening a socket makes an
	 * endpoint; binding one chooses WHERE ON THIS HOST it answers.
	 */
	KOF_CAP_NET_BIND = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_BIND),
	/*
	 * AND WAITING TO BE CALLED - listen.
	 *
	 * SEPARATE FROM BIND, and the signatures are the argument:
	 *
	 *     bind(fd, struct sockaddr *addr, socklen_t len)
	 *     listen(fd, int backlog)
	 *
	 * bind carries an ADDRESS and listen carries only how deep the
	 * queue is. A bind on its own is a datagram socket picking its
	 * source port, or a client choosing which interface it goes out of
	 * - neither of them a service. listen is the one that says this
	 * program is waiting to be reached, and that is the fact worth its
	 * own word: a bot that connects out and a bot that waits are two
	 * shapes, and `net-open, net-bind, net-listen, net-accept` says
	 * which one this is at every step.
	 *
	 * They were ONE word here for a revision, on the argument that a
	 * listen always follows a bind so the pair is one act. The
	 * arguments say otherwise - the reverse does not hold, and the
	 * half that does not hold is exactly the one a rule needs to tell
	 * apart.
	 */
	KOF_CAP_NET_LISTEN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_LISTEN),
	/*
	 * READING AND WRITING A DESCRIPTOR - the words are `file-read` and
	 * `file-write`, beside `file-open`. They read as plain `read` and
	 * `write` for a while, which said the verb and left out what it was
	 * done to; the socket half has its own pair - see KOF_CAP_NET_READ.
	 */
	KOF_CAP_READ = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_READ),
	KOF_CAP_WRITE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_WRITE),
	KOF_CAP_FILE_OPEN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_OPEN),
	KOF_CAP_MEMFD = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_MEM, KOF_CA_MEM_MEMFD_CREATE),        /* a file that never touches a filesystem */
	/*
	 * RUNNING A FILE - execve, execveat. The word is `exec-file`, which
	 * pairs with `exec-register` for running memory; `exec-image` named
	 * neither half of that distinction.
	 */
	KOF_CAP_EXEC_IMAGE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_START),
	KOF_CAP_SPAWN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_FORK),        /* fork/vfork/clone - a separate ADDRESS SPACE */
	/*
	 * A THREAD, WHICH IS NOT A SMALLER PROCESS.
	 *
	 * clone with CLONE_THREAD, pthread_create, CreateThread. Separate from
	 * SPAWN because the two are different powers for the rules that care:
	 * a dropper forks, runs something else and is done, while a FLOODER
	 * needs threads - they share the descriptor table and the address
	 * space, which is the whole reason it uses them. "Spawned something in
	 * a loop" cannot tell those apart and both of them do it.
	 *
	 * A thread created by a syscall is clone with the flag; one created
	 * through libc is a name. Both land here.
	 */
	KOF_CAP_THREAD = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_THREAD_CREATE),
	/*
	 * A RAW SOCKET - socket(.., SOCK_RAW, ..).
	 *
	 * Separate from NET_OPEN for the same reason ALLOC_EXEC is separate
	 * from ALLOC: it is a different power, not a different spelling. It
	 * needs CAP_NET_RAW, it lets the program write its own IP and TCP
	 * headers, and the reason to want that is to send packets a socket
	 * would not - a SYN flood, a spoofed source, a scan. Ordinary software
	 * asks for one about as often as it asks for ptrace.
	 */
	KOF_CAP_NET_RAW = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_OPEN_RAW),
	KOF_CAP_SLEEP = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_BARE, KOF_CA_BARE_SLEEP),
	/*
	 * REACHING INTO ANOTHER PROCESS - and the three of these are the
	 * Windows half of what ptrace is on Linux, split because the three
	 * steps are separately observable there and a rule wants them apart.
	 *
	 * PTRACE is the handle: ptrace(ATTACH), OpenProcess. PROC_MEM is
	 * writing or reading that process's memory. PROC_EXEC is making it
	 * run something: CreateRemoteThread, SetThreadContext, an APC queued
	 * onto its thread. "Opened a handle" is what a debugger and a task
	 * manager do; "opened a handle, wrote its memory and made it run" is
	 * not, and the vocabulary has to be able to say the difference.
	 */
	KOF_CAP_PTRACE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_OPEN),
	KOF_CAP_PROC_MEM = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_MEM_ACCESS),
	KOF_CAP_PROC_EXEC = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_CONTROL),
	/*
	 * RESOLVING AN IMPORT AT RUN TIME - GetProcAddress, dlsym.
	 *
	 * Measured over the PE objects here that produced no chain at all:
	 * GetProcAddress appears in 148 of them and LoadLibrary in 125, which
	 * makes it the commonest thing the vocabulary could not say. It is
	 * also what a loader does INSTEAD of having an import table, so its
	 * absence from a table and its presence in the code is the same fact
	 * seen twice.
	 *
	 * NOT A VERDICT ON ITS OWN, and more plainly than most: ordinary
	 * Windows software resolves imports this way all day. It is here to
	 * be ONE term among several, which is what every measured rule in
	 * this tree turned out to need.
	 */
	KOF_CAP_RESOLVE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_LIB, KOF_CA_LIB_API_RESOLVE),
	/*
	 * LOADING A LIBRARY - LoadLibrary, LdrLoadDll, dlopen.
	 *
	 * SPLIT OUT OF KOF_CAP_RESOLVE, which covered both halves of the
	 * same two-step and could say neither. Loading a library BRINGS CODE
	 * IN; resolving a symbol finds an address in code already there.
	 * They are ordered - the load comes first and the lookup needs it -
	 * and a chain that writes them with one word cannot show the order
	 * or the link between them. `lib-open` then `lib-resolve`, with the
	 * handle carrying the edge, is what the program did.
	 */
	KOF_CAP_LIB_OPEN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_LIB, KOF_CA_LIB_LOAD),
	/*
	 * TURNING A NAME INTO AN ADDRESS ON THE NETWORK - gethostbyname,
	 * getaddrinfo.
	 *
	 * ALSO SPLIT OUT OF KOF_CAP_RESOLVE, and this one was the worst of
	 * the three: a DNS lookup and a GetProcAddress have nothing in
	 * common but the English word, and the chain printed `resolve` in
	 * the middle of a socket sequence where it meant a domain name.
	 *
	 * AND IT IS NOT KOF_CAP_NET_ADDR either, which is the family it sits
	 * in. NET_ADDR is a program BUILDING an address it already knows -
	 * inet_addr, htons - and this is a program ASKING for one it does
	 * not. That is the difference between a hardcoded C2 and a domain,
	 * which is the difference between a sample that dies with its IP and
	 * one whose operator can move it.
	 */
	KOF_CAP_DNS = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_GETADDR),
	/*
	 * WRITING TO THE REGISTRY - RegSetValueEx and the key creation that
	 * precedes it. Reads are deliberately not here: a program reading its
	 * own configuration is every program.
	 */
	KOF_CAP_REG_SET = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_REG, KOF_CA_REG_SET),
	/*
	 * AND THREE WORDS THE KERNEL SIDE NEEDS, because a loadable module
	 * makes no syscalls at all - it IS the other side of them.
	 *
	 * A .ko has no mmap, no socket and no write. What it has is a list of
	 * UNDEFINED SYMBOLS, which is the same kind of declaration a PE import
	 * table is, read the same way - see kof_flow_cap_of_name. The three
	 * things a kernel rootkit cannot avoid doing have names there, and
	 * those names cannot vary, because they are the kernel's.
	 *
	 * MEASURED, against 1497 real kernel modules from two kernels on one
	 * machine and six distinct LKM rootkits:
	 *
	 *     prepare_creds -> commit_creds        5 of 6     0 of 1497
	 *     register_kprobe                      5 of 6     0 of 1497
	 *     list surgery, old spelling           2 of 6     0 of 1497
	 *     list surgery, _or_report spelling       -     255 of 1497
	 *
	 * The last row is why the third word is COMMON and not RARE, and it is
	 * the trap worth naming: `__list_del_entry_valid` resolves to nothing
	 * on 1497 clean modules, but the kernel renamed it to
	 * `__list_del_entry_valid_or_report` and the new name is in 17% of
	 * them. A rule written against the first name is a rule about one
	 * kernel version, not about hiding.
	 *
	 * WHAT THIS MEASUREMENT IS NOT: six samples, of three lineages. It is
	 * enough to choose the words with; it is not a corpus.
	 */
	/* prepare_creds / prepare_kernel_cred / commit_creds - a process's
	 * credentials REPLACED, which is what "give me root" compiles to. */
	KOF_CAP_CRED_SET = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_CRED, KOF_CA_CRED_MODIFY),
	/* register_kprobe, the ftrace filter calls, text_poke, set_memory_rw -
	 * putting code of one's own in the path of somebody else's. */
	KOF_CAP_HOOK = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_KMOD, KOF_CA_KMOD_HOOK),
	/* Taking an entry out of a kernel list: the module list, the task
	 * list, a directory's. Ordinary code does it too - see the measurement
	 * above - so this is a term and never a verdict. */
	KOF_CAP_LIST_HIDE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_KMOD, KOF_CA_KMOD_LIST_EDIT),
	/*
	 * A PROTECTION TURNED OFF, AND IT HAS NO NAME TO MATCH.
	 *
	 * `mov cr0, reg` with the write-protect bit cleared is how a kernel
	 * rootkit makes the kernel's own text writable before it patches a
	 * syscall table. Diamorphine calls that step "unprotect memory" in
	 * its source, and the compiled form is INLINE ASSEMBLY: no undefined
	 * symbol, nothing in any import table, invisible to every word above.
	 *
	 * So this one is read from the INSTRUCTION, which the x86 sweep can
	 * do and the name tables cannot. Measured: four of seven distinct LKM
	 * rootkits carry `mov cr,reg`, against 3 of 898 loadable modules from
	 * two live kernels - 0.33%, and the three are what they sound like,
	 * the modules that manage the CPU.
	 *
	 * WHY IT IS NOT FOLDED INTO HOOK. Hooking is putting code in a path;
	 * this is removing the obstacle to doing so. A rootkit does both and
	 * an ordinary module does neither, but they are two acts and a chain
	 * that can say both is worth more than one that says "hook" twice.
	 */
	KOF_CAP_PROT_OFF = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_KMOD, KOF_CA_KMOD_CR_WRITE),
	/*
	 * AN ADDRESS OR A PORT BUILT BY HAND.
	 *
	 * htons, htonl, inet_addr, inet_aton, inet_pton - the calls a program
	 * makes when it is assembling a sockaddr itself rather than being
	 * handed one by a resolver or a config file.
	 *
	 * CHOSEN BY THE RANKING AND NOT BY A GUESS, which matters because the
	 * same ranking rejected almost everything else. Over 1772 ELF malware
	 * objects against 20347 Linux binaries from this machine:
	 *
	 *     htons      5.2%  vs 0.06%      87x
	 *     ntohs      2.0%  vs 0.04%      50x
	 *     htonl      4.1%  vs 0.08%      51x
	 *     inet_addr 18.1%  vs 0.47%      38x
	 *
	 * Those are the four sharpest BEHAVIOUR names in the whole corpus.
	 * Everything that scored higher was toolchain - `__uClibc_main`,
	 * `_Jv_RegisterClasses`, `_gp_disp` - which separates perfectly here
	 * because the samples are old cross-compiled IoT builds and the clean
	 * side is a modern glibc distribution. A word made of those would
	 * mean "built with uClibc", and it would be right on this corpus and
	 * wrong on the first clean router firmware it met.
	 *
	 * WHAT IT IS NOT. It is not "talks to the network" - net-open already
	 * says that, and ordinary software resolves names all day. It is the
	 * program doing the resolver's job itself, which is what a bot with
	 * its address list compiled in has to do.
	 *
	 * AND THE RATES ABOVE ARE NOT WHAT A SCAN MEETS. They are rates
	 * within the objects that HAVE names, and malware here is statically
	 * linked while clean software is not - so per object the order
	 * reverses, 29 of 2416 botnet against 176 of 1260 clean. See
	 * the measured share below. The word is
	 * still worth having: it says something true that nothing else said,
	 * and what it is worth is a measurement and not a hope.
	 */
	KOF_CAP_NET_ADDR = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_ADDR),
	/*
	 * A PROCESS CHANGING WHAT IT LOOKS LIKE - prctl.
	 *
	 * prctl(PR_SET_NAME) is how a bot renames itself in the process
	 * table. Ordinary software does it too, which is why this is a term
	 * and not a verdict.
	 *
	 * setsid USED TO BE HERE AND IS NOT A DISGUISE. It leaves the
	 * controlling terminal, which is the first thing in every daemon
	 * ever written - the word claimed an intent the call does not carry.
	 * It is KOF_CAP_BACKGROUND now.
	 *
	 * AND THE RATE THAT WAS QUOTED HERE WAS FOR BOTH OF THEM: 15.4% of
	 * ELF malware against 1.20% of clean, measured over the pair. It is
	 * not this row's rate and is not repeated as one - neither half has
	 * been measured alone, and the weight both carry is the parent's
	 * until one is. Same rule the THREAD/NET_RAW split kept.
	 *
	 * NOT REFINED BY THE OPTION, which is this row's real weakness. A
	 * name resolves to a capability before any argument is read - see
	 * the resolver in nucleo.c - so PR_SET_NAME and PR_SET_DUMPABLE
	 * and PR_CAPBSET_DROP all arrive as the same word. Reported rather
	 * than guessed at.
	 */
	KOF_CAP_SELF_HIDE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_SELF_NAME),
	/*
	 * A PROCESS PUTTING ITSELF IN THE BACKGROUND - setsid.
	 *
	 * SPLIT OUT OF KOF_CAP_SELF_HIDE, where it was the wrong word.
	 * setsid leaves the controlling terminal, so the program keeps
	 * running when the shell or the ssh session that started it closes.
	 * That is what every daemon does and what a payload does when it
	 * means to still be there tomorrow. It is not a disguise, and
	 * "self-hide" put an intent in the chain that the evidence does not
	 * hold.
	 *
	 * NEAR fork, NOT near prctl - see family() in diagnose.c. Forking
	 * and detaching are the same move for a program that wants to go on
	 * running without the thing that started it, which is why a variant
	 * that does one where another did the other is the same program.
	 */
	KOF_CAP_BACKGROUND = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_BACKGROUND),
	/*
	 * CONTROL LEAVING THROUGH A REGISTER, INTO MEMORY THIS PROGRAM MADE
	 * EXECUTABLE.
	 *
	 * Named for the MECHANISM and not for the destination, because the
	 * mechanism is what the sweep actually read: an indirect branch whose
	 * register holds what an earlier step returned - a page from mmap, a
	 * region from mprotect, a buffer from VirtualAlloc. "Into memory" is
	 * the consequence and is already said by the link.
	 *
	 * Nothing a compiler emits does this: a program's own code is in its
	 * own sections and is reached by direct branches.
	 *
	 * IT WAS A FLAG AND THAT WAS NOT ENOUGH. KOF_FLOWF_EXECUTED says the
	 * same thing attached to the ALLOCATION, which puts the most telling
	 * fact of a stager in a footnote on a step that happens at the start
	 * - and leaves the chain with no step at the point where the program
	 * actually hands itself over. The msfvenom stager reads
	 * `mmap, socket, connect, sleep` and the thing it exists to do is
	 * absent. The flag stays, because a rule written against it still
	 * matches; this is the same fact given a position in the sequence.
	 *
	 * The link says WHICH step produced the memory - see
	 * kof_flow_node.from - so a reader sees `jump v1` and a rule can ask
	 * for the pair rather than for either half.
	 */
	KOF_CAP_EXEC_REG = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_MEM, KOF_CA_MEM_EXEC),
	/*
	 * FINDING THE LIBRARIES WITHOUT ASKING THE LOADER.
	 *
	 * The evidence is a segment-relative read of the thread block at the
	 * offset the OS puts its loader data: fs:[0x30] on 32-bit Windows,
	 * gs:[0x60] on 64-bit. From there a program walks the module list
	 * itself and finds exports by hand.
	 *
	 * WHY THIS IS A CAPABILITY AND NOT A DECODE. The payloads that do it
	 * resolve each API by HASHING its name, and the hash is seeded per
	 * build: measured on one MSF evasion sample, the loop is seeded with
	 * 0xcd8099a0 where the stock one starts at zero, and not one of its
	 * eleven constants matches a table built for the stock algorithm.
	 * Chasing that is chasing a value the author picks - he can change
	 * the seed, the rotation, the whole function. What he cannot change
	 * is 0x30: the OS put the loader there and a program that looks
	 * somewhere else finds nothing.
	 *
	 * So this records THAT the program resolves its own imports, which
	 * is the behaviour, and says nothing about which ones - that is the
	 * part a rule does not need and cannot rely on.
	 *
	 * IT IS AN ATOM AND NOT A VERDICT. A packer does this, a reflective
	 * loader does this, and so does a little legitimate code that reads
	 * PEB->BeingDebugged. The combination is a rule's to ask for.
	 */
	KOF_CAP_SELF_RESOLVE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_LIB, KOF_CA_LIB_PEB_WALK),
	/*
	 * A STRING BEING FOLDED INTO A NUMBER INSIDE A LOOP.
	 *
	 * The companion of KOF_CAP_SELF_RESOLVE and the reason the pair is
	 * worth more than either: having found the module list by hand, a
	 * payload matches each export by hashing its name, so no API name
	 * is anywhere in the file.
	 *
	 * READ AS A SHAPE. The literature calls it "ror 13" and 13 is
	 * exactly the part an author can change; so can the seed, which one
	 * measured sample sets to 0xcd8099a0 where the stock algorithm
	 * starts at zero. What survives is a rotate of a register that is
	 * also accumulated into, inside a loop over a string.
	 *
	 * ORDINARY CODE ROTATES TOO - a CRC, a hash table, a PRNG - which is
	 * why this is an atom and not a verdict, and why the loop is part of
	 * the test rather than the rotate alone.
	 */
	KOF_CAP_NAME_HASH = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_LIB, KOF_CA_LIB_NAME_HASH),
	/*
	 * A CALL THROUGH A REGISTER THAT HOLDS THIS OBJECT'S OWN CODE.
	 *
	 * The third member of the set above, and the one that says what the
	 * other two are FOR. Having walked the loader data and hashed the
	 * names, the payload does not call the API it found by name - it
	 * calls a dispatcher it built itself, and picks the destination with
	 * a number:
	 *
	 *     call   next            ; next:
	 *     pop    ebp             ; ebp = my own address
	 *     ...
	 *     push   0xe719ffac      ; which one
	 *     call   *%ebp           ; the dispatcher
	 *
	 * SO THE CALL GRAPH IS EMPTY ON PURPOSE. Every API the program uses
	 * goes through one instruction, and a reader that follows names sees
	 * a body with no imports, no syscalls and nothing to say about it.
	 * Measured on one MSF evasion stager: nineteen API calls, zero of
	 * them visible as a call to anything.
	 *
	 * WHAT IS NOT RECORDED is which number was pushed. The hash seed is
	 * the author's to choose - the same sample reseeds it - so a rule
	 * that read the selector would be reading a value that changes
	 * between builds of the same payload. The shape does not change: he
	 * can move the seed but not the fact that he has to reach his own
	 * code without being told where it is.
	 *
	 * NOT THE SAME AS KOF_CAP_EXEC_REG, which is a branch into memory an
	 * earlier step produced. This one is a branch into memory that was
	 * already there, and the two want different rules.
	 */
	KOF_CAP_CALL_REG = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_LIB, KOF_CA_LIB_CALL_REGISTER),
	/*
	 * ================= EVENTS THE VOCABULARY HAD NO WORD FOR =========
	 *
	 * Found by reading the two name tables against what a program can
	 * actually ask an operating system for, rather than by meeting a
	 * sample. Every one of these is an event with a NAMED, SINGLE-PURPOSE
	 * entry point - which is the bar for being here. The ones left out are
	 * left out on purpose and listed at the end of this block.
	 */
	/*
	 * BULK ENCRYPTION OR DECRYPTION.
	 *
	 * The event ransomware is, and there was no word for it: a file read,
	 * a file write and a file open, which is also what a backup is. What
	 * separates them is the cipher in between, and both platforms have one
	 * narrow way to ask for it - CryptEncrypt / BCryptEncrypt on Windows,
	 * the EVP and AES entry points of OpenSSL on Linux.
	 *
	 * NOT A VERDICT: an updater checks signatures and a backup tool
	 * encrypts. Read against open-read-write-delete over a directory walk
	 * it is something else, and that reading is a rule's to make.
	 */
	KOF_CAP_CRYPTO = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_CRYPTO, KOF_CA_CRYPTO_ANY),
	/*
	 * TAKING WHAT THE USER IS DOING - keystrokes, the clipboard, the
	 * screen.
	 *
	 * Spyware's defining event and the one least like anything else:
	 * SetWindowsHookEx with WH_KEYBOARD_LL, GetAsyncKeyState in a loop,
	 * GetClipboardData. A program that reads the keyboard outside its own
	 * window is doing one thing.
	 *
	 * WHAT IS DELIBERATELY NOT HERE is the screen. BitBlt and GetDC are
	 * how every drawing program on Windows draws, so a screenshot cannot
	 * be told from a repaint by the name, and putting them here would
	 * have made this word mean "has a window".
	 */
	KOF_CAP_CAPTURE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_INPUT, KOF_CA_INPUT_CAPTURE),
	/*
	 * INSTALLING ITSELF AS A SERVICE.
	 *
	 * Persistence that survives a reboot and runs as SYSTEM, and the SCM
	 * is the only way to ask for it. Installers do this too, which is why
	 * it is an atom; what it is NOT is ambiguous about what happened.
	 */
	KOF_CAP_SVC_INSTALL = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_SERVICE, KOF_CA_SERVICE_INSTALL),
	/*
	 * PUTTING CODE IN THE KERNEL FROM USERLAND.
	 *
	 * init_module, finit_module and NtLoadDriver load a module; bpf()
	 * attaches a program the kernel will run on events. The second is here
	 * because the modern Linux implant is an eBPF one - it needs no module
	 * to be signed, it survives lsmod, and the vocabulary could not say it
	 * had happened.
	 *
	 * delete_module is the same word: taking a module out is how one
	 * rootkit unloads a monitor.
	 */
	KOF_CAP_MOD_LOAD = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_KMOD, KOF_CA_KMOD_LOAD),
	/*
	 * A NAMED PIPE OR FIFO.
	 *
	 * How a backdoor is reached without a listening socket - the beacon
	 * that speaks over SMB, and the Unix reverse shell built out of
	 * `mkfifo` and two redirections. An anonymous pipe is NOT this word:
	 * every shell pipeline is one.
	 */
	KOF_CAP_PIPE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PIPE, KOF_CA_PIPE_NAMED_CREATE),
	/*
	 * REMOVING A FILE, OR MOVING IT OUT FROM UNDER ITS NAME.
	 *
	 * The end of a dropper (delete the installer), the end of a wiper, and
	 * half of what ransomware does to the original. Ordinary software
	 * unlinks temporary files constantly, so this is COMMON company - it
	 * is here so that a chain can SAY it, not so that it can decide.
	 */
	KOF_CAP_FILE_DELETE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_DELETE),
	/*
	 * CHANGING A FILE'S PERMISSIONS.
	 *
	 * Specifically: a dropper writes a payload and has to make it
	 * runnable. `write` then `chmod` on the same path is a shape, and
	 * without this word the second half was invisible.
	 */
	KOF_CAP_PERM_SET = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_PERM_SET),
	/*
	 * ASKING WHETHER IT IS BEING DEBUGGED.
	 *
	 * Only the entry points whose entire purpose is the question -
	 * IsDebuggerPresent, CheckRemoteDebuggerPresent, and hiding a thread
	 * from the debugger. The timing tricks are NOT here: GetTickCount and
	 * QueryPerformanceCounter are how every program measures anything.
	 */
	KOF_CAP_ANTI_DEBUG = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_BARE, KOF_CA_BARE_ANTI_DEBUG),
	/*
	 * CHANGING WHAT THE PROCESS CAN SEE - chroot, pivot_root, setns,
	 * unshare.
	 *
	 * Two opposite uses and one event: a daemon locking itself down, and a
	 * container escape joining the host's namespaces. Which one it is
	 * depends on the direction and on what the process did next, so the
	 * word records that the boundary moved and leaves the rest to a rule.
	 */
	KOF_CAP_JAIL = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NS, KOF_CA_NS_CHANGE),
	/*
	 * ===== AND THREE MORE, FOUND BY MEASUREMENT RATHER THAN BY READING
	 * A HEADER. Every imported name in 10243 objects of two corpora was
	 * counted and the ones this vocabulary had no word for were ranked;
	 * what came out on top was C runtime boilerplate - CloseHandle,
	 * HeapAlloc, GetLastError - which is the exclusion policy below
	 * being right. These three are what was left after it.
	 */
	/*
	 * POINTING A STANDARD DESCRIPTOR SOMEWHERE ELSE.
	 *
	 * `dup2(sock, 0); dup2(sock, 1); dup2(sock, 2); execve("/bin/sh")`
	 * IS the Unix reverse shell, and the vocabulary could see the socket
	 * and the execve and not the three lines that join them. 217 of the
	 * measured objects import dup2 and nothing accounted for it.
	 *
	 * A shell does this too, for every pipeline it builds. What a shell
	 * does not do is reach the descriptor from a socket.
	 */
	KOF_CAP_FD_REDIR = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_FD_REDIRECT),
	/*
	 * SETTING A FILE'S TIMESTAMPS.
	 *
	 * There is one reason to write a time onto a file after writing the
	 * file, and it is so that the file does not look new. An archiver
	 * restoring an mtime is the honest use and it is a narrow one.
	 */
	KOF_CAP_TIMESTOMP = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_TIMESTAMP_SET),
	/*
	 * READING THE LIST OF RUNNING PROCESSES.
	 *
	 * Held out of the exclusion list below, which rejects directory
	 * enumeration, because the two are not alike: readdir is how every
	 * program walks a folder, while CreateToolhelp32Snapshot exists to
	 * do this and nothing else. Measured at about 2% of the objects
	 * here, against readdir's 4% in a corpus where readdir is also what
	 * every archiver calls.
	 *
	 * WHAT IT IS FOR, either way: finding a process to inject into, or
	 * finding the one that would notice.
	 */
	KOF_CAP_PROC_LIST = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PROC, KOF_CA_PROC_ENUM),
	/*
	 * READING FROM, AND WRITING TO, A SOCKET.
	 *
	 * `read` is `read` whether the descriptor came from `open` or from
	 * `socket`, and the vocabulary said so - one word for both. That is
	 * the wrong grain for the shape that matters most: a program that
	 * reads a FILE into executable memory is a loader, and one that
	 * reads a SOCKET into executable memory is a stager, and those are
	 * not the same finding.
	 *
	 * HOW IT IS KNOWN. Two ways, and both are the engine's rather than a
	 * reader's. Some names say it outright - recv, recvfrom, WSARecv,
	 * InternetReadFile - and for the rest it is THE EDGE: the descriptor
	 * argument links back to a step whose capability is net-open,
	 * net-accept or net-raw. That is the same link the chain already
	 * carries, read for what it means instead of only displayed.
	 *
	 * A `read` whose descriptor cannot be followed stays KOF_CAP_READ.
	 * The absence of an edge is not evidence of a file.
	 */
	/*
	 * The words are `net-recv` and `net-send`, after the calls they
	 * come from - recvfrom and sendto. They read as `net-read` and
	 * `net-write` for a while, which named the direction twice and the
	 * act not at all.
	 */
	KOF_CAP_NET_READ = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_RECV),
	KOF_CAP_NET_WRITE = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_NET, KOF_CA_NET_SEND),
	/*
	 * AN ANONYMOUS PIPE, AND IT IS NOT A FINDING.
	 *
	 * KOF_CAP_PIPE says so where it is defined: every shell pipeline
	 * is one, and a word that fires on all of them says nothing. That
	 * reasoning stands and this does not contradict it.
	 *
	 * It exists because `pipe(fds)` MAKES TWO DESCRIPTORS, and the
	 * thing that matters is what is done with them: `pipe` then
	 * `dup2` onto stdout then `execve` is a shell whose output goes
	 * somewhere, which is the shape of every remote shell there is.
	 * The `dup2` can only say that if there is something to point at.
	 *
	 * So this is a step that exists to be the HEAD OF A LINK. A chain
	 * that does not use it drops it, by the same rule that drops an
	 * unused mapping, so the shell pipeline the reasoning above warns
	 * about never reaches a page.
	 */
	KOF_CAP_PIPE_OPEN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_PIPE, KOF_CA_PIPE_CREATE),
	/*
	 * MOVING A FILE OUT FROM UNDER ITS NAME.
	 *
	 * Split from KOF_CAP_FILE_DELETE, which used to carry it. The
	 * classification was right - a dropper that renames the installer
	 * away and one that unlinks it are doing the same thing to the
	 * same file - but the WORD was not: the page said `file-delete`
	 * with `rename()` written beside it, which is the engine
	 * contradicting itself in one line.
	 *
	 * Kept apart rather than renamed, because the two are not the
	 * same to a reader: ransomware renames what it encrypted and
	 * keeps it, a wiper does not.
	 */
	KOF_CAP_FILE_RENAME = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_FILE, KOF_CA_FILE_RENAME),
	/*
	 * A HEAP BUFFER, AND IT IS NOT A FINDING EITHER.
	 *
	 * Every C program calls malloc, so the word on its own says
	 * nothing - the same objection the list below makes to `pipe`,
	 * and it is answered the same way: this exists to be the HEAD OF
	 * A LINK and nothing else.
	 *
	 * `buf = malloc(n)` then `read(fd, buf, n)` then `write(1, buf,
	 * k)` is one buffer carrying a file's contents out, and the two
	 * transfers can only be joined if the buffer has a name. A stack
	 * buffer gets one from its frame slot - see cmap.pk - and a
	 * heap one had none at all, so the second half of every
	 * read-then-send was a step with `_` where the link should be.
	 * MEASURED on a gcc -O0 build with eight links written into the
	 * source: seven were found and this was the one missing.
	 *
	 * NOT KOF_CAP_ALLOC, although both hand back memory. That word
	 * goes through prot_cap, which reads an argument as an mmap
	 * protection - and malloc's first argument is a SIZE, so
	 * `malloc(7)` would have been reported as `alloc-exec`. Heap
	 * memory is not executable without an mprotect, which already
	 * has its own word.
	 *
	 * Dropped by the same rule as the pipe when nothing consumes it,
	 * so a program that merely allocates never reaches a page.
	 */
	KOF_CAP_HEAP = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_MEM, KOF_CA_MEM_ALLOC_HEAP),
	/*
	 * AN OPEN REGISTRY KEY, AND IT IS NOT A FINDING.
	 *
	 * The row above KOF_CAP_REG_SET says the vocabulary takes registry
	 * WRITES only, because a program reading its own configuration is
	 * every program. That still holds and this does not contradict it:
	 * `RegOpenKeyEx` is not the read, it is where the HANDLE comes from,
	 * and `RegSetValueEx(hKey, "Run", ...)` had nothing to point at
	 * without it. The same shape as KOF_CAP_PIPE_OPEN, answered the same
	 * way - a step that exists to be the head of a link, dropped by the
	 * prune when nothing consumes it.
	 *
	 * MEASURED over 128 unpacked PE from the corpus: RegOpenKeyExW is
	 * imported by 39 of them and RegOpenKeyExA by 15, against
	 * RegSetValueExW's own count - every one of those writes was a step
	 * with `_` where the key should be.
	 */
	KOF_CAP_REG_OPEN = KOF_CAP_MK(KOF_CCTX_USER, KOF_CG_REG, KOF_CA_REG_OPEN),
	/*
	 * ================= AND WHAT WAS LEFT OUT, WITH WHY =================
	 *
	 * These are events too, and each was considered and rejected because
	 * the name that carries them is also the name ordinary software uses.
	 * Writing them down so the next reader does not re-derive the list:
	 *
	 *   directory enumeration   FindFirstFile, readdir, getdents - every
	 *                           archiver, backup tool and indexer. The
	 *                           PROCESS list is a different question and
	 *                           has a word; see KOF_CAP_PROC_LIST.
	 *   file probing            access, stat, lstat - 253, 109 and 20 of
	 *                           the measured objects, and every one of
	 *                           them is "does this exist".
	 *   random numbers          CryptGenRandom, BCryptGenRandom - a key
	 *                           needs one and so does a session id.
	 *   identity                getuid, geteuid - "am I root" is asked
	 *                           by every program that can be installed.
	 *   ioctl                   267 objects, and the verb is in the
	 *                           argument. See the note below.
	 *   timing                  GetTickCount, QueryPerformanceCounter,
	 *                           rdtsc - every program that measures.
	 *   host identity           GetComputerName, GetUserName, uname,
	 *                           GetSystemInfo - every installer.
	 *   single instance         CreateMutex - every desktop application.
	 *   COM and WMI             CoCreateInstance - all of Windows.
	 *   screen drawing          BitBlt, GetDC - see KOF_CAP_CAPTURE.
	 *   signals                 kill, sigaction - every supervisor.
	 *   anonymous pipes         pipe, pipe2 - every shell pipeline.
	 *
	 * What they have in common is that the NAME is not the evidence; the
	 * evidence would be the argument (which directory, which key, how
	 * often) or the company it keeps. Both are things this vocabulary
	 * cannot hold, so adding them would add noise and no claim.
	 */
	/* Not a count any more - the values are sparse. Kept as the end
	 * marker the enum needs and nothing indexes by it. */
	KOF_CAP_LAST
};

/*
 * AND THE CEILING, which is a bitmask and was two words away without saying so.
 *
 * A function's capabilities are kept as `1ull << cap` in kof_flow_func.mask,
 * in kof_obj_probe.cap_mask and in kof_diag_mask. While that shift was `1u`
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
 * `1ull << cap` is gone: the mask is `1ull << KOF_CAP_GROUP(cap)` and there
 * are sixteen groups, so the vocabulary can grow a word whenever the thing
 * it names is real. What is bounded is the number of ACTIONS inside one
 * group, because the dense index below multiplies by a fixed stride - and
 * that bound is checked here rather than discovered by a profile entry
 * landing on its neighbour.
 */
typedef char kof_cap_groups_fit[(KOF_CG_COUNT <= 64) ? 1 : -1];

/*
 * A DENSE SLOT PER CAPABILITY, for the arrays that cannot be sparse.
 *
 * The value carries three fields so it is not a small number any more, and
 * kof_pth_profile indexes two arrays by capability. This maps it to a dense
 * slot. The stride is the real limit on actions per group; the assert above
 * does not catch that, so every table that fills a group is written against
 * it and KOF_CAP_ACT_MAX says so out loud.
 */
#define KOF_CAP_ACT_MAX   16u
#define KOF_CAP_DENSE(c)  ((unsigned)(KOF_CAP_GROUP(c) * KOF_CAP_ACT_MAX \
			   + KOF_CAP_ACT(c)))
#define KOF_CAP_DENSE_MAX ((unsigned)(KOF_CG_COUNT * KOF_CAP_ACT_MAX))
/* A value that could have come from KOF_CAP_MK and nothing else. Replaces
 * `cap < KOF_CAP_COUNT`, which stopped meaning anything when the values
 * stopped being consecutive. */
#define KOF_CAP_VALID(c) ((c) && KOF_CAP_GROUP(c) < KOF_CG_COUNT && \
			  KOF_CAP_ACT(c) && KOF_CAP_ACT(c) < KOF_CAP_ACT_MAX)

const char *kof_flow_cap_name(uint16_t cap);

/* What to call the thing this capability PRODUCES, when a later step is
 * handed it - "sock", "mem", "lib". NULL for a step that makes nothing.
 * See kof_flow_cap_makes, which is the same set. */
const char *kof_flow_cap_noun(uint16_t cap);

/* Which argument of this step is a string - index plus one, or 0. The
 * name matters: `openat` takes the path second. */
uint8_t kof_flow_text_arg(uint16_t cap, uint16_t name);

/* Which argument this step writes its result through - index plus one,
 * or 0. See the note in nucleo.c. */
uint8_t kof_flow_out_arg(uint16_t cap);

/*
 * WHETHER THIS WORD NAMES A STEP THAT MAKES SOMETHING, so that a later step
 * can hold it. A link is a variable - see the note in nucleo.c - and its head
 * has to be a word that produces one.
 */
int kof_flow_cap_makes(uint16_t cap);

/* The selector was known only in its low 8 bits - "mov al, 3" with the rest of
 * eax never set in this sweep. Accepted because a syscall number under 256 is
 * fully determined by it, and flagged because the claim is weaker. */
#define KOF_FLOWF_LOW8   (1u << 0)
/*
 * The node sits inside a backward branch's span.
 *
 * "Sends TCP" and "sends TCP in a loop" are different claims and the second is
 * the one worth a rule - a bot's beacon, a scanner's probe, a stager's retry.
 * APPROXIMATED BY AN INTERVAL, not by a dominator: a backward direct branch
 * from S to T marks everything in [T, S]. That over-reports when two unrelated
 * loops nest and under-reports a loop built out of indirect branches, and both
 * are stated here rather than discovered later.
 */
#define KOF_FLOWF_LOOP   (1u << 1)
/*
 * WHAT THIS NODE PRODUCED WAS LATER USED AS A BRANCH TARGET.
 *
 * This is the edge the whole file exists for. "Allocated something executable"
 * is a fact about a JIT as much as about a stager; "allocated something
 * executable AND JUMPED INTO IT" is a different claim, and it is the one a
 * rule wants. The pointer is followed from the register the call returned it
 * in to the operand of an indirect call or jump.
 *
 * REGISTER TO REGISTER ONLY. A pointer spilled to the stack and reloaded is
 * lost - that needs the slot model xref.c has and this does not. Losing it
 * costs a detection; inventing it would cost a false one, so the sweep loses.
 */
#define KOF_FLOWF_EXECUTED (1u << 2)
/*
 * THE IMPORT WAS CALLED THROUGH A REGISTER, not through its slot.
 *
 * `call [VirtualAlloc]` is what a compiler emits and what a reader of the
 * import table can see at the call site. `mov edi,[VirtualAlloc] ; ... ; call
 * edi` reaches the same function while leaving nothing at the call site that
 * names it - which is the point: it is one of the cheapest ways to make a
 * static reader lose the reference.
 *
 * NOT A VERDICT. A compiler does this too when the same import is called in a
 * loop, so on its own it says very little. It is a fact about HOW the call was
 * written, and what it is worth is measured beside the others.
 */
#define KOF_FLOWF_VIA_REG  (1u << 3)
/*
 * THE PAGE IS WRITABLE AND EXECUTABLE AT THE SAME TIME.
 *
 * WHY THIS IS NOT THE SAME FACT AS ALLOC_EXEC, and keeping it separate is the
 * difference between a rule and a false positive.
 *
 *     a JIT:     allocate READ|WRITE, emit into it, THEN flip it to
 *                READ|EXEC. The page is never both at once - W^X, which
 *                every serious runtime has followed for twenty years.
 *
 *     a loader:  allocate READ|WRITE|EXEC in one call, copy, jump. One call,
 *                and the page is both for its whole life.
 *
 * Both reach this file as "allocated something executable", because the
 * capability vocabulary deliberately does not name the API. That is right for
 * telling mmap from VirtualAlloc and WRONG here: these two are different
 * SHAPES, and normalising them together would put every JIT in the same bucket
 * as every stager. So the shape is kept, as a bit on the node.
 *
 * POSIX spells it PROT_WRITE|PROT_EXEC; Windows spells it
 * PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY.
 */
#define KOF_FLOWF_WX       (1u << 4)

/*
 * THE SOCKET IS A DATAGRAM ONE - socket(.., SOCK_DGRAM, ..).
 *
 * "Opened a socket" is one claim and "opened a socket it will not connect"
 * is another. A C2 is a stream: connect, read a command, write a reply. A UDP
 * FLOOD is a datagram socket and sendto in a loop, with no connect anywhere -
 * so without this the two shapes differ only by the absence of a step, which
 * is the weakest thing a rule can be built on.
 */
#define KOF_FLOWF_DGRAM    (1u << 5)
/*
 * THE SOCKET IS LOCAL - socket(AF_UNIX, ..) - AND THAT IS A CLEAN SIGNAL.
 *
 * Desktop IPC is sockets: language servers, extension hosts, session buses.
 * bases/heur/proc_revshell_00.c measured eight such processes on an ordinary
 * desktop, every one of them legitimate. A rule that says "talks on a socket"
 * and means the network is wrong on all eight of them, and the domain
 * argument is what separates them - not the protocol, not the port.
 *
 * It is kept as a POSITIVE fact rather than as "not AF_INET", because an
 * argument the sweep could not follow is a third state and must not read as
 * either answer.
 */
#define KOF_FLOWF_LOCAL    (1u << 6)
/*
 * THE CAPABILITY WAS READ FROM A NAME, not from a number or an instruction.
 *
 * Every word in this vocabulary comes from something the AUTHOR did not
 * choose - a syscall number the kernel ABI fixes, an instruction the ISA
 * fixes, a symbol the kernel or Windows owns and a program cannot rename and
 * still link. None of it is content in the sense plague means.
 *
 * But the three are not equally hard to AVOID, and that difference is worth
 * carrying. A number is in the instruction stream of anything that asks the
 * kernel for something; a `mov cr0` is there or it is not. A NAME can be
 * sidestepped: resolve the address at run time and call through a register
 * and there is no name left - diamorphine does precisely that to find the
 * syscall table, and 926 Go binaries here do it for every Windows API they
 * use.
 *
 * So this bit says "this step is the avoidable kind". A rule that wants to
 * stand up to an author who tried can require steps without it; one written
 * for triage can take them as they come. The engine states the difference
 * rather than deciding it.
 */
#define KOF_FLOWF_BY_NAME  (1u << 7)

#define KOF_FLOW_ARGS 4u

/*
 * THE RULE SHAPE STOOD HERE - kof_pth_step and kof_pth_symptom, a sequence
 * of steps with a distance back to the one that fed each.
 *
 * It is gone with the chain. Three things it could not hold and each is the
 * ordinary case: one producer with several consumers is a TREE and not a
 * list; a step joined to another by CONTROL rather than by a value has no
 * row in a sequence at all, which is how `vfork` then `execl("/bin/sh")`
 * came off a page that had already found both; and a DISTANCE in a sequence
 * is changed by inserting one step between two, which makes it the one part
 * of a rule an author can break on purpose.
 *
 * What replaces it is a set of relations between nodes - a producer named by
 * its ROLE in the rule and not by how far back it sits - which is both
 * insertion-proof and canonicalisable, and therefore hashable.
 *
 * What stays in this file is the VOCABULARY above: the capability words and
 * the three tables that answer for them. Those are the unit a gene is built
 * from and they did not depend on the chain.
 */


#endif /* KOFMOD_KOFCAP_H */
