#include <kofmod/kofpathogen.h>

/*
 * kernel_giveroot_00.c - a kernel module taking root for the running task.
 *
 * "Give me root", as a C compiler emits it:
 *
 *     newcreds = prepare_creds();
 *     newcreds->uid.val = newcreds->gid.val = 0;
 *     newcreds->euid.val = newcreds->egid.val = 0;
 *     newcreds->suid.val = newcreds->sgid.val = 0;
 *     newcreds->fsuid.val = newcreds->fsgid.val = 0;
 *     commit_creds(newcreds);
 *
 * which the compiler writes as four eight-byte stores of a literal zero,
 * each one an immediate in the instruction:
 *
 *     48 c7 40 04 00 00 00 00   mov QWORD PTR [rax+0x4],0x0
 *     48 c7 40 0c 00 00 00 00   mov QWORD PTR [rax+0xc],0x0
 *     48 c7 40 14 00 00 00 00   mov QWORD PTR [rax+0x14],0x0
 *     48 c7 40 1c 00 00 00 00   mov QWORD PTR [rax+0x1c],0x0
 *
 *
 * ---- WHY THIS IS A PROOF AND NOT A RARITY ARGUMENT ----------------------
 *
 * THE OLD VERSION STATED prepare_creds -> commit_creds AND NOTHING ELSE,
 * and leaned on a measurement to make that mean something: 0 of 900 clean
 * kernel modules carry the pair. That is a statement about a corpus, not
 * about the file. It answers "this resembles no clean module I have seen",
 * which is a different and weaker question from "this file takes root" -
 * and it is the question that goes wrong the first time a legitimate module
 * does something unusual. nfsd is already the beginning of that: it is the
 * one clean user of prepare_creds here, because it builds credentials to
 * act for a remote user.
 *
 * WHAT SEPARATES THE TWO IS THE VALUE. nfsd writes the remote user's ids;
 * this writes ZERO, and uid 0 is root by the operating system's own
 * definition - not by anything the author chose and not by anything a
 * corpus says. See KOF_DIAG_B_VAL for why a value may be matched on here
 * when the vocabulary refuses values everywhere else.
 *
 * NO OFFSET IS NAMED, deliberately. struct cred's layout moves between
 * kernel versions and configurations - CONFIG_UIDGID_STRICT_TYPE_CHECKS
 * alone changes the field types - so a rule naming +0x4 would be a rule
 * about one build. The statement here is layout free: SOMETHING in the
 * object was set to zero. The object's identity comes from its producer,
 * which is the whole reason the link is the evidence: the engine does not
 * need to know the struct, it knows this is what prepare_creds returned.
 *
 * MEASURED ACROSS GENERATIONS. Two Diamorphine builds here were compiled
 * against different kernels; eight imported symbols differ between them -
 * __kmalloc became __kmalloc_noprof, current_task became const_current_task,
 * the list helpers gained _or_report. prepare_creds and commit_creds are in
 * both, because they are what the rootkit is FOR. A diagnose anchored on
 * the allocator or the list helpers would have died at that kernel bump.
 *
 * ONE BEHAVIOUR, ONE ANSWER. This needs no graph kept for a later pass:
 * the tree IS the evidence, so a rule reads it as kof_diag(DIAG_LKM_GIVEROOT)
 * and has everything. A behaviour that needs counting or needs a list of
 * what was touched - a syscall table being patched - is the other kind, and
 * that one does read the graph.
 */

KOF_DIAG_NAME(DIAG_LKM_GIVEROOT);

/*
 * BOTH ROUTES, AND NEITHER IS OPTIONAL.
 *
 * SYMBOL finds the two calls: in a .ko a call is `e8 00 00 00 00` and the
 * target lives in the relocation table, so nothing else can see them.
 *
 * EMULATE is what reads a store's displacement and its immediate off the
 * instruction. It CANNOT run alone on a relocatable object - measured, the
 * emulate route by itself produces zero nodes on diamorphine.ko, because
 * there is no entry point and it navigates between sites the symbol route
 * placed. A diagnose that asked for EMULATE alone would match nothing and
 * say nothing about why.
 */
KOF_DIAG_VIA(KOF_DIAG_VIA_SYMBOL | KOF_DIAG_VIA_EMULATE);

/*
 * ---- THE SIGNS THAT SAY THIS OBJECT IS WORTH THE WALK -------------------
 *
 * A RELOCATABLE OBJECT, which on Linux is a loadable kernel module. The
 * engine publishes the object kind; this registers the condition. Said
 * explicitly rather than inferred from the symbols: an ordinary program can
 * import a name that matches, and a .ko has no PT_LOAD, so the walk takes
 * an entirely different path through it.
 *
 * AND BOTH HALVES OF THE PAIR. A sign is a filter and not evidence - it may
 * be wrong and cost only the analysis - but these two are also what the
 * tree below is about, so an object missing either cannot match anyway.
 */
KOF_DIAG_WHEN(KOF_FACT_OBJ_KIND, KOF_ELF_REL);
KOF_DIAG_NEEDS("prepare_creds", "commit_creds");

/*
 * THE ANCHOR IS prepare_creds AND NOT commit_creds, although commit is the
 * moment it takes effect.
 *
 * Matching starts at the root and descends, so the root should be the end
 * that comes FIRST in the provenance: commit_creds consumes what
 * prepare_creds produced, and a tree rooted the other way round would have
 * to search backwards from every install.
 */
KOF_DIAG_ANCHOR(p, KOF_NUCLEO_CRED_PREPARE, 0);

/*
 * THE CREDENTIAL WAS ZEROED. role BUFFER: the memory written IS the object
 * prepare_creds returned.
 */
KOF_DIAG_FROM(z, p, KOF_NUCLEO_FIELD_WRITE, KOF_DIAG_ROLE_BUFFER);
KOF_DIAG_WROTE(z, 0);

/*
 * AND THEN INSTALLED. Two unrelated calls in one module would satisfy a
 * rule that only counted them; the link is what makes it one statement.
 */
KOF_DIAG_FROM(c, p, KOF_NUCLEO_CRED_SET, KOF_DIAG_ROLE_BUFFER);
