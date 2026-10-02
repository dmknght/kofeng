/*
 * kofmod/kofpathogen.h - THE CAPABILITY VOCABULARY, and the shapes made of it.
 *
 * WHY IT IS A MODULE HEADER AND NOT AN ENGINE ONE.
 *
 * A rule used to reach this vocabulary only through a reference chain the
 * generator wrote for it - the words were the engine's and a rule carried
 * numbers. Now a rule NAMES them: kof_pth_has(KOF_CAP_ALLOC_EXEC,
 * KOF_FLOWF_WX) is a sentence a researcher writes, so the words have to be
 * where a researcher's file can see them.
 *
 * It is the gene vocabulary in ESET's sense of the word: the features a
 * sample is reduced to before anything is compared. What a profile made of
 * them looks like is the scanner's business; what they MEAN is here.
 *
 * NOTHING IN THIS FILE READS AN OBJECT. It is names and widths only, so it
 * costs a rule nothing to include and carries no dependency but <stdint.h>.
 */
#ifndef KOFMOD_KOFPATHOGEN_H
#define KOFMOD_KOFPATHOGEN_H

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
enum kof_flow_cap {
	KOF_CAP_NONE = 0,
	KOF_CAP_ALLOC,        /* a mapping, without execute permission */
	KOF_CAP_ALLOC_EXEC,   /* ... with it - mmap/mprotect and PROT_EXEC */
	KOF_CAP_NET_OPEN,     /* socket */
	KOF_CAP_NET_CONNECT,
	KOF_CAP_NET_ACCEPT,
	KOF_CAP_READ,         /* read/recvfrom */
	KOF_CAP_WRITE,        /* write/sendto */
	KOF_CAP_FILE_OPEN,
	KOF_CAP_MEMFD,        /* a file that never touches a filesystem */
	KOF_CAP_EXEC_IMAGE,   /* execve/execveat */
	KOF_CAP_SPAWN,        /* fork/vfork/clone - a separate ADDRESS SPACE */
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
	KOF_CAP_THREAD,
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
	KOF_CAP_NET_RAW,
	KOF_CAP_SLEEP,
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
	KOF_CAP_PTRACE,
	KOF_CAP_PROC_MEM,
	KOF_CAP_PROC_EXEC,
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
	KOF_CAP_RESOLVE,
	/*
	 * WRITING TO THE REGISTRY - RegSetValueEx and the key creation that
	 * precedes it. Reads are deliberately not here: a program reading its
	 * own configuration is every program.
	 */
	KOF_CAP_REG_SET,
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
	KOF_CAP_CRED_SET,
	/* register_kprobe, the ftrace filter calls, text_poke, set_memory_rw -
	 * putting code of one's own in the path of somebody else's. */
	KOF_CAP_HOOK,
	/* Taking an entry out of a kernel list: the module list, the task
	 * list, a directory's. Ordinary code does it too - see the measurement
	 * above - so this is a term and never a verdict. */
	KOF_CAP_LIST_HIDE,
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
	KOF_CAP_PROT_OFF,
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
	 * kof_diag_weight, which weighs it by the second number. The word is
	 * still worth having: it says something true that nothing else said,
	 * and what it is worth is a measurement and not a hope.
	 */
	KOF_CAP_NET_ADDR,
	/*
	 * A PROCESS CHANGING WHAT IT LOOKS LIKE - prctl, setsid.
	 *
	 * 15.4% of ELF malware against 1.20% of clean, which is 13x and the
	 * best of the non-network rows. prctl(PR_SET_NAME) is how a bot
	 * renames itself in the process table; setsid is how it leaves the
	 * terminal that started it. Both are things ordinary daemons also do,
	 * which the rate says plainly - this is a term and not a verdict.
	 */
	KOF_CAP_SELF_HIDE,
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
	KOF_CAP_EXEC_REG,
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
	KOF_CAP_SELF_RESOLVE,
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
	KOF_CAP_NAME_HASH,
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
	KOF_CAP_CALL_REG,
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
	KOF_CAP_CRYPTO,
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
	KOF_CAP_CAPTURE,
	/*
	 * INSTALLING ITSELF AS A SERVICE.
	 *
	 * Persistence that survives a reboot and runs as SYSTEM, and the SCM
	 * is the only way to ask for it. Installers do this too, which is why
	 * it is an atom; what it is NOT is ambiguous about what happened.
	 */
	KOF_CAP_SVC_INSTALL,
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
	KOF_CAP_MOD_LOAD,
	/*
	 * A NAMED PIPE OR FIFO.
	 *
	 * How a backdoor is reached without a listening socket - the beacon
	 * that speaks over SMB, and the Unix reverse shell built out of
	 * `mkfifo` and two redirections. An anonymous pipe is NOT this word:
	 * every shell pipeline is one.
	 */
	KOF_CAP_PIPE,
	/*
	 * REMOVING A FILE, OR MOVING IT OUT FROM UNDER ITS NAME.
	 *
	 * The end of a dropper (delete the installer), the end of a wiper, and
	 * half of what ransomware does to the original. Ordinary software
	 * unlinks temporary files constantly, so this is COMMON company - it
	 * is here so that a chain can SAY it, not so that it can decide.
	 */
	KOF_CAP_FILE_DELETE,
	/*
	 * CHANGING A FILE'S PERMISSIONS.
	 *
	 * Specifically: a dropper writes a payload and has to make it
	 * runnable. `write` then `chmod` on the same path is a shape, and
	 * without this word the second half was invisible.
	 */
	KOF_CAP_PERM_SET,
	/*
	 * ASKING WHETHER IT IS BEING DEBUGGED.
	 *
	 * Only the entry points whose entire purpose is the question -
	 * IsDebuggerPresent, CheckRemoteDebuggerPresent, and hiding a thread
	 * from the debugger. The timing tricks are NOT here: GetTickCount and
	 * QueryPerformanceCounter are how every program measures anything.
	 */
	KOF_CAP_ANTI_DEBUG,
	/*
	 * CHANGING WHAT THE PROCESS CAN SEE - chroot, pivot_root, setns,
	 * unshare.
	 *
	 * Two opposite uses and one event: a daemon locking itself down, and a
	 * container escape joining the host's namespaces. Which one it is
	 * depends on the direction and on what the process did next, so the
	 * word records that the boundary moved and leaves the rest to a rule.
	 */
	KOF_CAP_JAIL,
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
	KOF_CAP_FD_REDIR,
	/*
	 * SETTING A FILE'S TIMESTAMPS.
	 *
	 * There is one reason to write a time onto a file after writing the
	 * file, and it is so that the file does not look new. An archiver
	 * restoring an mtime is the honest use and it is a narrow one.
	 */
	KOF_CAP_TIMESTOMP,
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
	KOF_CAP_PROC_LIST,
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
	KOF_CAP_NET_READ,
	KOF_CAP_NET_WRITE,
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
	KOF_CAP_COUNT
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
typedef char kof_cap_fits_in_mask[(KOF_CAP_COUNT <= 64) ? 1 : -1];

const char *kof_flow_cap_name(uint8_t cap);

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
 * A CALL CHAIN, AS SOMETHING A RULE CAN CARRY.
 *
 * What the code DOES: which capabilities it asks the system for, in order,
 * which of them carry a program-level flag, and which took an argument an
 * earlier one produced. See detectors/overlord/pathogen/diagnose.h for how one is read out of
 * code, and kof_pth_match in kofmod/kofsig.h for how a rule asks about one.
 *
 * NO ADDRESSES AND NO INDICES. kof_flow_node - the engine's working record -
 * holds a virtual address, a function number and a step count, and none of
 * those survives a rebuild or belongs in a signature. What survives is the
 * shape, and a stored chain is exactly the shape.
 *
 * Fixed and small, because a rule's reference lands in the module's .rodata
 * beside its strings and its block hashes, and a reference that needed an
 * allocation would be one somebody has to remember to free.
 */
struct kof_pth_step {
	uint8_t cap;    /* enum kof_flow_cap - analyzers/parsers/binaries/disasm/flow.h */
	/*
	 * The KOF_FLOWF_* bits that are about the PROGRAM: in a loop, the
	 * value was later branched to, the import was called through a
	 * register, the page is writable and executable at once. The bit that
	 * says how confidently the selector was decoded is not one of them and
	 * is never stored - that would be a rule about the decoder.
	 */
	uint8_t flags;
	/*
	 * THE LINK, as a distance and not an index.
	 *
	 * "Its buffer came from the step two before it" is the same claim in
	 * every build; "its buffer came from node 674" is a fact about one
	 * file. Only the first argument carrying one is kept: a rule that
	 * pinned all four would be pinning the calling convention.
	 *
	 * AND IT IS THE ONLY THING THAT FIXES AN ORDER. A compiler may open
	 * the socket before it maps the page or after, and both are the same
	 * program - so the match is order-free EXCEPT where a step consumes
	 * what an earlier one produced, which no layout can reverse. See
	 * kof_diag_pct.
	 *
	 * 0 means no link was seen, which is NOT the same as "there is none":
	 * the sweep loses a pointer spilled to the stack, and on a PE that is
	 * nearly all of them.
	 */
	uint8_t back;
	/*
	 * THE NAME IT WAS READ FROM, or 0 for "any name with this capability".
	 *
	 * The capability is the portable claim and stays the default: a rule
	 * that had to list `register_kprobe` and `ftrace_set_filter_ip` would
	 * be a rule about one kernel's way of hooking.
	 *
	 * But a capability is sometimes TOO wide, and the measurement says
	 * where. Over 900 loadable modules from two live kernels: the word
	 * `cred-set` matches one of them - nfsd, which builds credentials to
	 * impersonate its clients, and means it - while the NAME
	 * `commit_creds` matches none. `list-hide` matches nineteen, because
	 * the kernel renamed its list check and the new name is ordinary;
	 * `__list_del_entry_valid` matches none.
	 *
	 * So a step may pin the name when the capability is not enough, and a
	 * researcher writing "register_kprobe, then mov_cr0, then a write"
	 * gets a sentence rather than three words that could be anything.
	 * Zero is what every rule written before this says, and it still
	 * means the same thing.
	 */
	uint16_t name;
};

/* Long enough for every shape measured so far - the longest chain holding an
 * alloc-exec in 1500 PE samples was 19 steps - and short enough that the
 * alignment table stays a few hundred cells. */
#define KOF_PTH_SYMPTOM_MAX 24u

struct kof_pth_symptom {
	struct kof_pth_step s[KOF_PTH_SYMPTOM_MAX];
	uint8_t n;
};


#endif /* KOFMOD_KOFPATHOGEN_H */
