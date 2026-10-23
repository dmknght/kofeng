/*
 * kofmod/kofcap.h - THE CAPABILITY VOCABULARY, as a module sees it.
 *
 * THE ABI RE-EXPORTS kgenome's TYPE. The capability words, the (context,
 * group, action) packing and the node flags are what the diagnose walk
 * produces (kgenome_nucleo_cap_name and the other tables are defined in
 * libgenome/celllysis/nucleo.c), so the vocabulary is defined once, in
 * libgenome/celllysis/capability.h, with the long note on what a node means.
 * A rule reaches it through this name.
 */
#ifndef KOFMOD_KOFCAP_H
#define KOFMOD_KOFCAP_H

#include <celllysis/capability.h>

/* module-facing names: the lib defines KGENOME_*, the ABI keeps the old spelling.
 * Object-like macros, so a module (and the signature language) still writes the
 * old name, `struct cell_insn` and `enum kof_arch` included. Engine code uses
 * the KGENOME_ / kgenome_ name. */
#define KOF_FLOWF_WX                       KGENOME_NUCLEO_F_WX
#define KOF_FLOWF_BUILT                    KGENOME_NUCLEO_F_BUILT
#define KOF_NUCLEO_ACTION_READ             KGENOME_NUCLEO_ACTION_READ
#define KOF_NUCLEO_ACTION_WRITE            KGENOME_NUCLEO_ACTION_WRITE
#define KOF_NUCLEO_ALLOC                   KGENOME_NUCLEO_ALLOC
#define KOF_NUCLEO_ALLOC_EXEC              KGENOME_NUCLEO_ALLOC_EXEC
#define KOF_NUCLEO_ANTI_DEBUG              KGENOME_NUCLEO_ANTI_DEBUG
#define KOF_NUCLEO_BACKGROUND              KGENOME_NUCLEO_BACKGROUND
#define KOF_NUCLEO_CALL_REG                KGENOME_NUCLEO_CALL_REG
#define KOF_NUCLEO_CAPTURE                 KGENOME_NUCLEO_CAPTURE
#define KOF_NUCLEO_COPY_FROM_USER          KGENOME_NUCLEO_COPY_FROM_USER
#define KOF_NUCLEO_COPY_TO_USER            KGENOME_NUCLEO_COPY_TO_USER
#define KOF_NUCLEO_CRED_PREPARE            KGENOME_NUCLEO_CRED_PREPARE
#define KOF_NUCLEO_CRED_SET                KGENOME_NUCLEO_CRED_SET
#define KOF_NUCLEO_CRYPTO                  KGENOME_NUCLEO_CRYPTO
#define KOF_NUCLEO_DECODE                  KGENOME_NUCLEO_DECODE
#define KOF_NUCLEO_EVAL                    KGENOME_NUCLEO_EVAL
#define KOF_NUCLEO_CREATE                  KGENOME_NUCLEO_CREATE
#define KOF_NUCLEO_DYNCALL                 KGENOME_NUCLEO_DYNCALL
#define KOF_NUCLEO_DYNLOAD                 KGENOME_NUCLEO_DYNLOAD
#define KOF_NUCLEO_REQUEST                 KGENOME_NUCLEO_REQUEST
#define KOF_NUCLEO_DNS                     KGENOME_NUCLEO_DNS
#define KOF_NUCLEO_EXEC_IMAGE              KGENOME_NUCLEO_EXEC_IMAGE
#define KOF_NUCLEO_EXEC_REG                KGENOME_NUCLEO_EXEC_REG
#define KOF_NUCLEO_FD_NONBLOCK             KGENOME_NUCLEO_FD_NONBLOCK
#define KOF_NUCLEO_FD_REDIR                KGENOME_NUCLEO_FD_REDIR
#define KOF_NUCLEO_FILE_DELETE             KGENOME_NUCLEO_FILE_DELETE
#define KOF_NUCLEO_FILE_OPEN               KGENOME_NUCLEO_FILE_OPEN
#define KOF_NUCLEO_FILE_RENAME             KGENOME_NUCLEO_FILE_RENAME
#define KOF_NUCLEO_HEAP                    KGENOME_NUCLEO_HEAP
#define KOF_NUCLEO_HOOK                    KGENOME_NUCLEO_HOOK
#define KOF_NUCLEO_HTTP_CONNECT            KGENOME_NUCLEO_HTTP_CONNECT
#define KOF_NUCLEO_HTTP_FETCH              KGENOME_NUCLEO_HTTP_FETCH
#define KOF_NUCLEO_HTTP_OPEN               KGENOME_NUCLEO_HTTP_OPEN
#define KOF_NUCLEO_HTTP_RECV               KGENOME_NUCLEO_HTTP_RECV
#define KOF_NUCLEO_HTTP_SEND               KGENOME_NUCLEO_HTTP_SEND
#define KOF_NUCLEO_JAIL                    KGENOME_NUCLEO_JAIL
#define KOF_NUCLEO_KPROBE_REG              KGENOME_NUCLEO_KPROBE_REG
#define KOF_NUCLEO_KPROBE_UNREG            KGENOME_NUCLEO_KPROBE_UNREG
#define KOF_NUCLEO_KSYM_LOOKUP             KGENOME_NUCLEO_KSYM_LOOKUP
#define KOF_NUCLEO_LIB_OPEN                KGENOME_NUCLEO_LIB_OPEN
#define KOF_NUCLEO_LIST_HIDE               KGENOME_NUCLEO_LIST_HIDE
#define KOF_NUCLEO_MEMFD                   KGENOME_NUCLEO_MEMFD
#define KOF_NUCLEO_MEM_READ                KGENOME_NUCLEO_MEM_READ
#define KOF_NUCLEO_MEM_WRITE               KGENOME_NUCLEO_MEM_WRITE
#define KOF_NUCLEO_MOD_LOAD                KGENOME_NUCLEO_MOD_LOAD
#define KOF_NUCLEO_NAME_HASH               KGENOME_NUCLEO_NAME_HASH
#define KOF_NUCLEO_NET_ACCEPT              KGENOME_NUCLEO_NET_ACCEPT
#define KOF_NUCLEO_NET_ADDR                KGENOME_NUCLEO_NET_ADDR
#define KOF_NUCLEO_NET_BIND                KGENOME_NUCLEO_NET_BIND
#define KOF_NUCLEO_NET_CONNECT             KGENOME_NUCLEO_NET_CONNECT
#define KOF_NUCLEO_NET_HDRINCL             KGENOME_NUCLEO_NET_HDRINCL
#define KOF_NUCLEO_NET_LISTEN              KGENOME_NUCLEO_NET_LISTEN
#define KOF_NUCLEO_NET_OPEN                KGENOME_NUCLEO_NET_OPEN
#define KOF_NUCLEO_NET_RAW                 KGENOME_NUCLEO_NET_RAW
#define KOF_NUCLEO_NET_READ                KGENOME_NUCLEO_NET_READ
#define KOF_NUCLEO_NET_WRITE               KGENOME_NUCLEO_NET_WRITE
#define KOF_NUCLEO_PERM_SET                KGENOME_NUCLEO_PERM_SET
#define KOF_NUCLEO_PIPE                    KGENOME_NUCLEO_PIPE
#define KOF_NUCLEO_PIPE_OPEN               KGENOME_NUCLEO_PIPE_OPEN
#define KOF_NUCLEO_PROC_EXEC               KGENOME_NUCLEO_PROC_EXEC
#define KOF_NUCLEO_PROC_LIST               KGENOME_NUCLEO_PROC_LIST
#define KOF_NUCLEO_PROC_MEM                KGENOME_NUCLEO_PROC_MEM
#define KOF_NUCLEO_PROT_OFF                KGENOME_NUCLEO_PROT_OFF
#define KOF_NUCLEO_PTRACE                  KGENOME_NUCLEO_PTRACE
#define KOF_NUCLEO_READ                    KGENOME_NUCLEO_READ
#define KOF_NUCLEO_REG_OPEN                KGENOME_NUCLEO_REG_OPEN
#define KOF_NUCLEO_REG_SET                 KGENOME_NUCLEO_REG_SET
#define KOF_NUCLEO_RESOLVE                 KGENOME_NUCLEO_RESOLVE
#define KOF_NUCLEO_SELF_HIDE               KGENOME_NUCLEO_SELF_HIDE
#define KOF_NUCLEO_SELF_RESOLVE            KGENOME_NUCLEO_SELF_RESOLVE
#define KOF_NUCLEO_SLEEP                   KGENOME_NUCLEO_SLEEP
#define KOF_NUCLEO_SPAWN                   KGENOME_NUCLEO_SPAWN
#define KOF_NUCLEO_SVC_INSTALL             KGENOME_NUCLEO_SVC_INSTALL
#define KOF_NUCLEO_SYMBOL_GET              KGENOME_NUCLEO_SYMBOL_GET
#define KOF_NUCLEO_THREAD                  KGENOME_NUCLEO_THREAD
#define KOF_NUCLEO_TIMESTOMP               KGENOME_NUCLEO_TIMESTOMP
#define KOF_NUCLEO_WRITE                   KGENOME_NUCLEO_WRITE
#define kof_flow_cap                       kgenome_nucleo_cap
#define kof_flow_cap_name                  kgenome_nucleo_cap_name

#endif /* KOFMOD_KOFCAP_H */
