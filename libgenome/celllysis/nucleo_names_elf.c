/*
 * nucleo_names_elf.c - what an imported name means in an ELF object: libc, the Linux system interface and the kernel's own symbols (a module).
 *
 * One table of imported (or called) NAMES per target, each in the same capability vocabulary: what a program IS asked to do
 * is the one thing a rule can share between targets, and which API spells it is not. Looked up through
 * kgenome_nucleo_cap_of_name and its siblings (nucleo.c), which are told the target.
 */

#include "nucleo_private.h"

static const struct kgenome_nucleo_namerow rows[] = {
	/* POSIX */
	{ .name = "mmap", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "mmap64", .cap = KGENOME_NUCLEO_ALLOC },
	{ .name = "mprotect", .cap = KGENOME_NUCLEO_ALLOC },
	/* Not a finding on its own - see KGENOME_NUCLEO_HEAP - and here so that a
	 * buffer two transfers share has a name. posix_memalign is left
	 * out: it hands the pointer back THROUGH one, and nothing here
	 * carries an output argument, so the step would make something
	 * nothing could hold. */
	{ .name = "malloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "calloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "realloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "reallocarray", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "aligned_alloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "memalign", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "_Znwm", .cap = KGENOME_NUCLEO_HEAP },  /* new    */
	{ .name = "_Znam", .cap = KGENOME_NUCLEO_HEAP },  /* new[]  */
	{ .name = "socket", .cap = KGENOME_NUCLEO_NET_OPEN, .refine = KGENOME_NUCLEO_REFINE_SOCK },
	{ .name = "socketpair", .cap = KGENOME_NUCLEO_NET_OPEN },
	/* Not a finding on its own - see KGENOME_NUCLEO_PIPE_OPEN - and here so
	 * the step has a name and so a dynamically linked object calling
	 * pipe@plt reaches the same word as a static one. */
	{ .name = "pipe", .cap = KGENOME_NUCLEO_PIPE_OPEN },
	{ .name = "pipe2", .cap = KGENOME_NUCLEO_PIPE_OPEN },
	{ .name = "connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "accept4", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "bind", .cap = KGENOME_NUCLEO_NET_BIND },
	{ .name = "listen", .cap = KGENOME_NUCLEO_NET_LISTEN },
	{ .name = "recv", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "recvfrom", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "recvmsg", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "read", .cap = KGENOME_NUCLEO_MEM_READ },
	{ .name = "send", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "sendto", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "sendmsg", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "write", .cap = KGENOME_NUCLEO_MEM_WRITE },
	{ .name = "open", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "open64", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "openat", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "fopen", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "memfd_create", .cap = KGENOME_NUCLEO_MEMFD },
	{ .name = "execve", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execv", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execl", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execlp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "execvp", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "system", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "popen", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "fork", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "vfork", .cap = KGENOME_NUCLEO_SPAWN },
	/* The libc wrapper, whose flags are its THIRD argument rather than its
	 * first - a different convention from the syscall, and past what is
	 * refined here. It stays the weaker claim. */
	{ .name = "clone", .cap = KGENOME_NUCLEO_SPAWN },
	/* No flags to read and no ambiguity: the name IS the claim. */
	{ .name = "pthread_create", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "daemon", .cap = KGENOME_NUCLEO_SPAWN },
	{ .name = "sleep", .cap = KGENOME_NUCLEO_SLEEP },
	{ .name = "usleep", .cap = KGENOME_NUCLEO_SLEEP },
	{ .name = "nanosleep", .cap = KGENOME_NUCLEO_SLEEP },
	{ .name = "ptrace", .cap = KGENOME_NUCLEO_PTRACE },
	{ .name = "closesocket", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "dlopen", .cap = KGENOME_NUCLEO_LIB_OPEN },
	{ .name = "dlsym", .cap = KGENOME_NUCLEO_RESOLVE },

	/*
	 * THE ROWS THE RANKING CHOSE. Measured over the whole corpus here -
	 * 1772 ELF malware objects against 20347 Linux binaries - and kept
	 * because of what the numbers said, not because they sounded right.
	 * See KGENOME_NUCLEO_NET_ADDR for the rates and for what the ranking
	 * rejected.
	 */
	{ .name = "htons", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "htonl", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "ntohs", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "ntohl", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_addr", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_aton", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_pton", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_ntoa", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "inet_network", .cap = KGENOME_NUCLEO_NET_ADDR },
	{ .name = "gethostbyname", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "getaddrinfo", .cap = KGENOME_NUCLEO_DNS },
	{ .name = "prctl", .cap = KGENOME_NUCLEO_SELF_HIDE },
	{ .name = "setsid", .cap = KGENOME_NUCLEO_BACKGROUND },

	/*
	 * THE KERNEL, which is the same kind of table and a different side of
	 * the same machine.
	 *
	 * A loadable module makes no syscalls - it answers them - so the whole
	 * vocabulary above is silent on one. What it has instead is a list of
	 * UNDEFINED symbols, which is the same declaration a PE import table
	 * is: the names it was compiled against, fixed, and not the module's
	 * to choose. See KGENOME_NUCLEO_CRED_SET for the measurement that picked
	 * these.
	 *
	 * THE LINUX ONES HAVE NO PREFIX AND THAT IS A HAZARD worth stating:
	 * `kernel_read` and `filp_open` are kernel names, but nothing stops a
	 * userspace program exporting a function of the same name, and this
	 * table is consulted for both. Each row below is a name a userspace
	 * libc does not have, which is the only thing keeping the two apart.
	 *
	 * MEASURED, because a hazard without a number is a guess: across 1038
	 * objects from a frozen copy of /usr/bin, ZERO declare any of
	 * prepare_creds, commit_creds, prepare_kernel_cred, register_kprobe,
	 * kallsyms_lookup_name, kernel_read, kernel_write, filp_open,
	 * vfs_read, vfs_write, list_del, text_poke or sock_create. The hazard
	 * is real and it does not bite on real userspace - which is a fact
	 * about today's libraries, not a property of the design, so the rule
	 * for a new row stands: add a name only if userspace does not have it.
	 */
	/* Credentials BUILT, then credentials INSTALLED - "give me root" is
	 * the value passing from the first to the second, so the two halves
	 * have separate words. See KGENOME_NUCLEO_CRED_PREPARE. */
	{ .name = "prepare_creds", .cap = KGENOME_NUCLEO_CRED_PREPARE },
	{ .name = "prepare_kernel_cred", .cap = KGENOME_NUCLEO_CRED_PREPARE },
	/*
	 * ---- THE KERNEL'S ALLOCATORS ---------------------------------------
	 *
	 * Missing, and the gap showed up as a chain resting on nothing. A
	 * hooked getdents is
	 *
	 *     kdirent = kzalloc(n);  copy_from_user(kdirent, dirent, n);
	 *     <edit kdirent>;        copy_to_user(dirent, kdirent, n);
	 *
	 * and kdirent is the object the whole hook turns on. With no word for
	 * the allocation it was an anonymous stand-in - good enough to carry
	 * the link between the two copies, and unable to BE one end of it.
	 * The buffer that the listing is edited in should be a node.
	 *
	 * COMMON, as an allocator is: __kmalloc_noprof is in 177 of 900 clean
	 * kernel modules on this machine and kfree in 428. A term, never a
	 * verdict - what is said is not that a module allocates but what it
	 * then does with what it allocated.
	 *
	 * BOTH SPELLINGS of the kernel's recent renames, for the reason the
	 * list-surgery row gives: a table that knows only the old name is a
	 * table about one kernel version.
	 */
	{ .name = "__kmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "__kmalloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmalloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmalloc_trace", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kvmalloc_node", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kvmalloc_node_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "krealloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "krealloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmem_cache_alloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "kmem_cache_alloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "vmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "vmalloc_noprof", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "__vmalloc", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "__vmalloc_node_range", .cap = KGENOME_NUCLEO_HEAP },
	{ .name = "commit_creds", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "set_current_groups", .cap = KGENOME_NUCLEO_CRED_SET },
	/*
	 * A KPROBE PUT ON AND A KPROBE TAKEN OFF - two words, and neither of
	 * them is "hook". See KGENOME_NUCLEO_KPROBE_REG for why this row has now
	 * been wrong twice. The pair is the IDIOM: put a probe on a name,
	 * read kp.addr, take the probe away again, all in one function - and
	 * an idiom made of two calls needs two words to be written down.
	 * Measured at 0 of 900 clean modules on each side.
	 */
	{ .name = "register_kprobe", .cap = KGENOME_NUCLEO_KPROBE_REG },
	{ .name = "register_kprobes", .cap = KGENOME_NUCLEO_KPROBE_REG },
	{ .name = "unregister_kprobe", .cap = KGENOME_NUCLEO_KPROBE_UNREG },
	{ .name = "unregister_kprobes", .cap = KGENOME_NUCLEO_KPROBE_UNREG },
	/* A RETURN probe cannot read an address and leave; it exists to run
	 * code on somebody else's return, so it stays hooking. */
	{ .name = "register_kretprobe", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "unregister_kretprobe", .cap = KGENOME_NUCLEO_HOOK },
	/* Code of one's own put in the path of somebody else's. */
	{ .name = "unregister_ftrace_function", .cap = KGENOME_NUCLEO_HOOK },
	/*
	 * ---- write_cr0 / write_cr4 / mov_cr0 ARE OFF, ON PURPOSE --------
	 *
	 * The word is KGENOME_NUCLEO_PROT_OFF - "the module took write access to
	 * memory the kernel protects" - and these three are the only members
	 * it has. All three are x86, and two of them are the instruction
	 * rather than the behaviour, which is the one thing a nucleo word
	 * must never be: arm64 has no CR0 at all, and reaches the same end
	 * through update_mapping_prot, set_memory_rw or
	 * aarch64_insn_patch_text. A word that covers one architecture's
	 * mechanism makes rules that stop working on the next port, and
	 * leaving it half-populated is worse than leaving it empty, because
	 * a rule written against it would read as architecture-neutral.
	 *
	 * There is no LKM sample for any other architecture on this machine,
	 * so the membership cannot be measured yet. The value stays declared
	 * and nothing produces it until it can be.
	 */
	/* { .name = "write_cr0", .cap = KGENOME_NUCLEO_PROT_OFF }, */
	/* { .name = "write_cr4", .cap = KGENOME_NUCLEO_PROT_OFF }, */
	/*
	 * AND THE INSTRUCTION ITSELF, AS A NAME.
	 *
	 * `mov cr0, reg` has no symbol anywhere - it is inline assembly - so
	 * the node that reads it has nothing to put beside its capability and
	 * a reader sees "prot-off" with a dash. This row gives it a label.
	 *
	 * The underscore spelling is not a symbol anybody exports, so nothing
	 * can match this row by accident; it is reachable only by the sweep
	 * naming it directly.
	 */
	{ .name = "peb_ldr", .cap = KGENOME_NUCLEO_SELF_RESOLVE },
	{ .name = "name_hash", .cap = KGENOME_NUCLEO_NAME_HASH },
	/* off with the other two - see the note above them */
	/* { .name = "mov_cr0", .cap = KGENOME_NUCLEO_PROT_OFF }, */
	{ .name = "register_ftrace_function", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "ftrace_set_filter_ip", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "register_ftrace_direct", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "text_poke", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "text_poke_kgdb", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "set_memory_rw", .cap = KGENOME_NUCLEO_HOOK },
	{ .name = "set_memory_x", .cap = KGENOME_NUCLEO_HOOK },
	/*
	 * An entry taken out of a kernel list, or put into one. EVERY
	 * SPELLING, because the kernel renamed the check twice and a table
	 * that knows two of the three eras is still a table about kernel
	 * versions - see KGENOME_NUCLEO_LIST_HIDE, where the 17% that makes this
	 * a term and not a verdict is measured.
	 *
	 *   __list_del_entry              before the validator, pre-4.x
	 *   __list_del_entry_valid        4.x
	 *   __list_del_entry_valid_or_report  6.x
	 *
	 * MEASURED: the bare one was missing and hcrootkit - built for a 3.x
	 * kernel - produced no list node at all, so a diagnose about module
	 * self-removal matched Diamorphine and missed it, for no reason to do
	 * with what either of them does.
	 */
	{ .name = "__list_del_entry", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_del_entry_valid", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_del_entry_valid_or_report", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_add_valid", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "__list_add_valid_or_report", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "list_del", .cap = KGENOME_NUCLEO_LIST_HIDE },
	{ .name = "list_add", .cap = KGENOME_NUCLEO_LIST_HIDE },
	/*
	 * AND THE WORDS THE KERNEL NEEDS OF ITS OWN.
	 *
	 * kallsyms_lookup_name was called dlsym with a different name. It is
	 * not: dlsym returns what a library exported, this returns ANY symbol
	 * the kernel knows - and the one a rootkit wants, sys_call_table, is
	 * exported to nobody. See KGENOME_NUCLEO_KSYM_LOOKUP.
	 */
	/*
	 * ---- A CALL THROUGH A POINTER, WHICH IS AN IMPORT ON A RETPOLINE
	 * KERNEL ------------------------------------------------------------
	 *
	 * WHY THIS IS HERE AT ALL. A module that resolves a symbol at runtime
	 * does not call it by name - it stores the address in a variable and
	 * calls through that. Diamorphine's kallsyms_lookup_name_ is
	 * `uint64_t kallsyms_lookup_name_ = 0x0` in .bss, filled from kp.addr
	 * and then called. There is no symbol for that call, and the single
	 * most important call in the module was invisible.
	 *
	 * EXCEPT THAT ON A RETPOLINE BUILD THERE IS. The compiler does not
	 * emit `call *%rax`; it emits `call __x86_indirect_thunk_rax`, an
	 * UNDEFINED SYMBOL, which the relocation table lists like any other -
	 * and whose name states the register the target was in. So the site,
	 * the fact that it is indirect, and which register held the pointer
	 * all arrive without decoding anything.
	 *
	 * COMMON, AND THAT IS THE POINT OF SAYING SO: 359 of 900 clean kernel
	 * modules from this machine import one. It is a term and never a
	 * verdict - what matters is not that a module calls through a pointer
	 * but WHERE the pointer came from, which is a link.
	 *
	 * The register spellings are written out rather than matched by
	 * prefix: a prefix match would also take __x86_return_thunk, which is
	 * a return and not a call.
	 */
	{ .name = "__x86_indirect_thunk_rax", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rbx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rcx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rdx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rsi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rdi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_rbp", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r8", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r9", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r10", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r11", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r12", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r13", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r14", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_r15", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_eax", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_ebx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_ecx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_edx", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_esi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_edi", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "__x86_indirect_thunk_ebp", .cap = KGENOME_NUCLEO_CALL_REG },
	{ .name = "kallsyms_lookup_name", .cap = KGENOME_NUCLEO_KSYM_LOOKUP },
	{ .name = "kallsyms_lookup_name_t", .cap = KGENOME_NUCLEO_KSYM_LOOKUP },
	{ .name = "__symbol_get", .cap = KGENOME_NUCLEO_SYMBOL_GET },
	/* ACROSS THE USER/KERNEL BOUNDARY, which is not a file - see
	 * KGENOME_NUCLEO_COPY_FROM_USER. The rows under this one take a struct file
	 * and really are file I/O. */
	{ .name = "_copy_from_user", .cap = KGENOME_NUCLEO_COPY_FROM_USER },
	{ .name = "copy_from_user", .cap = KGENOME_NUCLEO_COPY_FROM_USER },
	{ .name = "__copy_from_user", .cap = KGENOME_NUCLEO_COPY_FROM_USER },
	{ .name = "_copy_to_user", .cap = KGENOME_NUCLEO_COPY_TO_USER },
	{ .name = "copy_to_user", .cap = KGENOME_NUCLEO_COPY_TO_USER },
	{ .name = "__copy_to_user", .cap = KGENOME_NUCLEO_COPY_TO_USER },
	{ .name = "kernel_read", .cap = KGENOME_NUCLEO_READ },
	{ .name = "kernel_write", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "vfs_read", .cap = KGENOME_NUCLEO_READ },
	{ .name = "vfs_write", .cap = KGENOME_NUCLEO_WRITE },
	{ .name = "filp_open", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "filp_close", .cap = KGENOME_NUCLEO_FILE_OPEN },
	{ .name = "call_usermodehelper", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "call_usermodehelper_exec", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	{ .name = "kthread_create_on_node", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "kthread_run", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "wake_up_process", .cap = KGENOME_NUCLEO_THREAD },
	{ .name = "sock_create", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "sock_create_kern", .cap = KGENOME_NUCLEO_NET_OPEN },
	{ .name = "kernel_connect", .cap = KGENOME_NUCLEO_NET_CONNECT },
	{ .name = "kernel_accept", .cap = KGENOME_NUCLEO_NET_ACCEPT },
	{ .name = "kernel_sendmsg", .cap = KGENOME_NUCLEO_NET_WRITE },
	{ .name = "kernel_recvmsg", .cap = KGENOME_NUCLEO_NET_READ },
	{ .name = "crypto_secretbox_easy", .cap = KGENOME_NUCLEO_CRYPTO },
	/* Code into the kernel. */
	{ .name = "init_module", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "finit_module", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "delete_module", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_load_program", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_prog_load", .cap = KGENOME_NUCLEO_MOD_LOAD },
	/*
	 * AND THE NAMES libbpf ACTUALLY EXPORTS, which are not the syscall's.
	 *
	 * The three above were written from the syscall and measured nothing:
	 * boopkit, an eBPF rootkit sitting in the corpus, reported no
	 * module-load at all. Nothing links `bpf` - a program built the
	 * normal way compiles its eBPF object into a SKELETON and calls
	 * bpf_object__load_skeleton and bpf_object__attach_skeleton, and
	 * libbpf makes the syscall from inside a shared library this engine
	 * never reads.
	 *
	 * Loading and attaching only. bpf_map_update_elem and the map
	 * accessors are how a loaded program is talked to afterwards and
	 * every eBPF program uses them, so they say nothing about whether
	 * this process put code in the kernel.
	 */
	{ .name = "bpf_object__load", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_object__load_skeleton", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_object__attach_skeleton", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_kprobe", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_uprobe", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_tracepoint", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_program__attach_xdp", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_prog_attach", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_set_link_xdp_fd", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "bpf_tc_attach", .cap = KGENOME_NUCLEO_MOD_LOAD },
	{ .name = "mkfifo", .cap = KGENOME_NUCLEO_PIPE },
	{ .name = "mkfifoat", .cap = KGENOME_NUCLEO_PIPE },
	/* MoveFileEx* used to be here as a DELETE. When KGENOME_NUCLEO_FILE_RENAME
	 * was split out of KGENOME_NUCLEO_FILE_DELETE the POSIX `rename` moved and
	 * these two did not, so the page went on saying `file-delete` with
	 * MoveFileExW beside it - the exact contradiction that split was
	 * made to end. They are with the other MoveFile rows now. */
	{ .name = "unlink", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "unlinkat", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "remove", .cap = KGENOME_NUCLEO_FILE_DELETE },
	{ .name = "rename", .cap = KGENOME_NUCLEO_FILE_RENAME },
	{ .name = "renameat", .cap = KGENOME_NUCLEO_FILE_RENAME },
	/* Making a dropped file runnable. */
	{ .name = "chmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fchmod", .cap = KGENOME_NUCLEO_PERM_SET },
	{ .name = "fchmodat", .cap = KGENOME_NUCLEO_PERM_SET },
	/* Moving the boundary of what it can see. */
	{ .name = "chroot", .cap = KGENOME_NUCLEO_JAIL },
	{ .name = "pivot_root", .cap = KGENOME_NUCLEO_JAIL },
	{ .name = "setns", .cap = KGENOME_NUCLEO_JAIL },
	{ .name = "unshare", .cap = KGENOME_NUCLEO_JAIL },
	/*
	 * AND WORDS FOR CAPABILITIES THAT ALREADY EXISTED, where only the
	 * spelling was missing. Changing one's own privileges is CRED_SET
	 * whether a kernel module calls commit_creds or a program calls
	 * setuid; reaching into another process is PROC_MEM whether it is
	 * WriteProcessMemory or process_vm_writev.
	 */
	{ .name = "setuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "setgid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "seteuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "setreuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "setresuid", .cap = KGENOME_NUCLEO_CRED_SET },
	{ .name = "process_vm_readv", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "process_vm_writev", .cap = KGENOME_NUCLEO_PROC_MEM },
	{ .name = "posix_spawn", .cap = KGENOME_NUCLEO_EXEC_IMAGE },
	/* The three measured ones. */
	{ .name = "dup2", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "dup3", .cap = KGENOME_NUCLEO_FD_REDIR },
	{ .name = "utime", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "utimes", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "utimensat", .cap = KGENOME_NUCLEO_TIMESTOMP },
	{ .name = "futimens", .cap = KGENOME_NUCLEO_TIMESTOMP },
};

const struct kgenome_nucleo_names kgenome_nucleo_names_elf = {
	.target = KGENOME_NUCLEO_T_ELF, .fold = 0, .row = rows, .n = sizeof rows / sizeof rows[0]
};
