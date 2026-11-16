/*
 * nucleo_capshape.c - THE SHAPE OF A CAPABILITY: what a call of the capability is, argument by argument, when the call has no row of
 * its own (a system call; a route that knows the capability and not the name; a row that writes no KGENOME_SHAPE).
 *
 * WHAT IT REPLACED, AND WHY IT IS NOT A SECOND PATH. Three switches answered these per capability: which argument is which input
 * (kgenome_diag_role_of_arg, diag_hit.c), whether the result is an object later calls are handed (kgenome_nucleo_hands_on) and
 * which argument names a kernel symbol (kgenome_nucleo_name_arg). Each is a column of a shape now, written here once per capability
 * and read by tools/gen_nucleo_index.py like a row's; a ROW's own shape replaces the capability's whole (it does not add to it),
 * so a row that differs says all of what it is. The answers below are the three switches' answers, unchanged: the capability's
 * shape is what the syscall routes and the routes without a name read, and a change to it is a change to every such route.
 *
 * Why these roles, from the switches' notes (kept): bytes through a descriptor - what is filled (BUFFER) and from where (FD), or what
 * is sent (SOURCE); across the user/kernel boundary one buffer each way, and they are different objects; a script's decode and
 * eval act on their first argument (VALUE); a data-call's first argument is the CALLEE (TARGET); the credentials installed are the
 * ones that were built, and both halves of a probe take the same struct kprobe (BUFFER). Why these results: a mapping, a heap block,
 * a socket, a file, a memfd, a pipe, a credential to edit and commit, and the address a kernel lookup found are each handed to a
 * later call; every other capability's answer is a status. The one name the old switch exempted (mprotect) is a row of the ELF table
 * now (res=status), which is where it always belonged.
 */
#include "nucleo_private.h"

const uint16_t kgenome_nucleo_capshape_cap[] = {
	KGENOME_NUCLEO_MEM_READ,       KGENOME_SHAPE("fd0 buf1")
	KGENOME_NUCLEO_READ,           KGENOME_SHAPE("fd0 buf1")
	KGENOME_NUCLEO_NET_READ,       KGENOME_SHAPE("fd0 buf1")
	KGENOME_NUCLEO_MEM_WRITE,      KGENOME_SHAPE("fd0 src1")
	KGENOME_NUCLEO_WRITE,          KGENOME_SHAPE("fd0 src1")
	KGENOME_NUCLEO_NET_WRITE,      KGENOME_SHAPE("fd0 src1")
	KGENOME_NUCLEO_COPY_FROM_USER, KGENOME_SHAPE("buf0 src1")
	KGENOME_NUCLEO_COPY_TO_USER,   KGENOME_SHAPE("buf0 src1")
	KGENOME_NUCLEO_NET_CONNECT,    KGENOME_SHAPE("fd0")
	KGENOME_NUCLEO_NET_BIND,       KGENOME_SHAPE("fd0")
	KGENOME_NUCLEO_NET_LISTEN,     KGENOME_SHAPE("fd0")
	KGENOME_NUCLEO_NET_ACCEPT,     KGENOME_SHAPE("fd0 res=handle")
	KGENOME_NUCLEO_FD_REDIR,       KGENOME_SHAPE("fd0")
	KGENOME_NUCLEO_FD_NONBLOCK,    KGENOME_SHAPE("fd0")
	KGENOME_NUCLEO_NET_HDRINCL,    KGENOME_SHAPE("fd0")
	KGENOME_NUCLEO_EXEC_IMAGE,     KGENOME_SHAPE("path0")
	KGENOME_NUCLEO_DECODE,         KGENOME_SHAPE("val0")
	KGENOME_NUCLEO_EVAL,           KGENOME_SHAPE("val0")
	KGENOME_NUCLEO_CREATE,         KGENOME_SHAPE("val0")
	KGENOME_NUCLEO_DYNCALL,        KGENOME_SHAPE("tgt0")
	KGENOME_NUCLEO_DYNLOAD,        KGENOME_SHAPE("tgt0")
	KGENOME_NUCLEO_CRED_SET,       KGENOME_SHAPE("buf0")
	KGENOME_NUCLEO_KPROBE_REG,     KGENOME_SHAPE("buf0 nameobj0")
	KGENOME_NUCLEO_KPROBE_UNREG,   KGENOME_SHAPE("buf0")
	KGENOME_NUCLEO_LIST_HIDE,      KGENOME_SHAPE("buf0")
	KGENOME_NUCLEO_ALLOC,          KGENOME_SHAPE("res=pointer")
	KGENOME_NUCLEO_ALLOC_EXEC,     KGENOME_SHAPE("res=pointer")
	KGENOME_NUCLEO_HEAP,           KGENOME_SHAPE("res=pointer")
	KGENOME_NUCLEO_NET_OPEN,       KGENOME_SHAPE("res=handle")
	KGENOME_NUCLEO_NET_RAW,        KGENOME_SHAPE("res=handle")
	KGENOME_NUCLEO_FILE_OPEN,      KGENOME_SHAPE("res=handle")
	KGENOME_NUCLEO_MEMFD,          KGENOME_SHAPE("res=handle")
	KGENOME_NUCLEO_PIPE_OPEN,      KGENOME_SHAPE("res=handle")
	KGENOME_NUCLEO_CRED_PREPARE,   KGENOME_SHAPE("res=pointer")
	KGENOME_NUCLEO_KSYM_LOOKUP,    KGENOME_SHAPE("name0 res=pointer")
	KGENOME_NUCLEO_SYMBOL_GET,     KGENOME_SHAPE("name0 res=pointer")
};

const uint32_t kgenome_nucleo_capshape_n = sizeof kgenome_nucleo_capshape_cap / sizeof kgenome_nucleo_capshape_cap[0];
