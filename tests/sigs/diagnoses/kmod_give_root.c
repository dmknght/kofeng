#include <kofmod/kofpathogen.h>

/*
 * tests/sigs/diagnoses/kmod_give_root.c
 *
 * A credential structure built, and then installed. "Give me root", as a C
 * compiler emits it.
 *
 * IT IS HERE AND NOT IN bases/ FOR THE SAME REASON rwx_exec IS: it is the
 * second fixture the diagnose chain is exercised against, and the first one
 * that reaches a KERNEL MODULE. A database the product ships should carry
 * diagnoses written as product, after a survey.
 *
 * WHY THIS SHAPE AND NOT THE ROOTKIT'S MORE FAMOUS PARTS. The syscall table
 * patch is what a rootkit is for, and it is the part this engine cannot
 * express yet - the table address comes back through a retpoline thunk and
 * the store into it is not a call, so neither end is a node. This one is
 * complete: both ends are imported symbols, the link between them is a value
 * in a register inside one function, and nothing about it depends on a
 * string the author chose.
 *
 * BOTH WORDS ARE RARE AND THE PAIR IS RARER. Measured on 900 clean kernel
 * modules from this machine: prepare_creds 0, commit_creds 0. The link is
 * what makes it a statement rather than two coincidences - a module may
 * legitimately touch credentials, but building one and installing it with
 * the uid fields zeroed in between is the whole of the privilege escalation.
 *
 * VIA SYMBOL ONLY. A loadable module makes no system calls; it answers them.
 * Declaring the route means a scan does not pay for a syscall sweep that
 * cannot find anything here.
 */

KOF_DIAG_NAME(kmod_give_root);
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYMBOL);

/*
 * THE ANCHOR IS prepare_creds AND NOT commit_creds, although commit is the
 * moment it takes effect.
 *
 * Matching starts at the root and descends, so the root should be the end
 * that comes FIRST in the provenance: commit_creds consumes what
 * prepare_creds produced, and a tree rooted the other way round would have
 * to search backwards from every install.
 */
KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_CRED_PREPARE, 0);

/*
 * AND THE LINK IS THE EVIDENCE, not the pair being present.
 *
 * role BUFFER: the credentials commit_creds installs ARE the struct
 * prepare_creds returned. Two unrelated calls in one module would satisfy a
 * rule that only counted them.
 */
KOF_DIAG_DECLARE_TAIL(KOF_NUCLEO_CRED_SET);

