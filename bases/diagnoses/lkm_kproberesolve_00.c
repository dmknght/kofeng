#include <kofmod/kofpathogen.h>

/*
 * lkm_kproberesolve_00.c - a kernel module obtaining the address of a kernel
 * symbol the kernel does not export, by planting a kprobe on it and reading
 * back where it landed.
 *
 *     register_kprobe(&kp);              kp.symbol_name = "kallsyms_lookup_name"
 *     addr = kp.addr;                    <- the resolved address
 *     unregister_kprobe(&kp);
 *     ((lookup_t)addr)("sys_call_table");
 *
 * The probe never fires. It exists to make the kernel resolve a name, and it
 * is taken down again before anything runs - which is what a hook would not
 * do, and what makes this a RESOLVER and not a hook. See
 * KOF_NUCLEO_KPROBE_REG for why the two words were split.
 *
 *
 * ---- WHAT THIS SAYS AND WHAT IT LEAVES TO THE NEXT STEP -----------------
 *
 * It says ONE thing: the module calls register_kprobe, with its pair
 * imported. That is the proof that the resolver is CALLED. It does not say
 * which name the module asked the kernel for, and it does not say what was
 * done with the address - the first is the list of strings handed to the
 * resolver, which is where the evidence about WHAT IS BEING HOOKED lives;
 * the second is a separate behaviour. Neither is read here.
 *
 * WHY NO LINK BETWEEN THE CALLS. The first version asked for the shape
 * register -> read the address -> unregister, and it fit Diamorphine and
 * missed hcrootkit, which does the same job in another order: two probes,
 * the first taken down BEFORE the address is read, the address kept in a
 * global and called through from four places. The shape is a habit of one
 * author. What both share is that the call is made, and that is what is
 * claimed.
 *
 * MEASURED across kernel generations. Both Diamorphine builds and both
 * hcrootkit builds import the pair, on kernels that differ in their
 * kallsyms export, their list helpers and eight other imported symbols -
 * and register_kprobe is imported by none of 900 clean kernel modules from
 * this machine.
 */

KOF_DIAG_NAME(DIAG_LKM_KPROBERESOLVE);

/*
 * BOTH ROUTES. SYMBOL finds the call; EMULATE is what reads the NAME the
 * probe was placed on out of the guest's memory and keeps it in the engine -
 * see capture_names. The name is not part of this diagnose's tree, but it is
 * part of what a verdict reading this diagnose asks next (kof_diag_str_has),
 * and the analysis runs only the routes the diagnoses it is serving declare.
 *
 * THIS WAS SYMBOL ALONE, on the reasoning that the call is all this claims.
 * Measured when a verdict first asked for the name: every condition was true
 * when forced through the engine's own calls and the verdict still did not
 * fire, because nothing had asked for the route that captures names, so the
 * store was empty and an empty store answers "not found". The cost is bounded
 * by the gate below - 0 of 900 clean modules import register_kprobe.
 */
KOF_DIAG_VIA(KOF_DIAG_VIA_SYMBOL | KOF_DIAG_VIA_EMULATE);

/*
 * ---- THE GATE: A RELOCATABLE OBJECT THAT IMPORTS THE PAIR ---------------
 *
 * 0 of 900 clean kernel modules import register_kprobe, so the analysis
 * never starts on one. Without a sign a diagnose runs on every kernel
 * module - measured once already, +47% on that corpus.
 */
KOF_DIAG_WHEN(KOF_FACT_OBJ_KIND, KOF_ELF_REL);
KOF_DIAG_NEEDS("register_kprobe", "unregister_kprobe");

/*
 * THE CALL IS THE ANCHOR. A kernel symbol imported by name is the narrowest
 * place there is to start from: the relocation table lists every site, so
 * finding the block to look at costs a table read and no decoding.
 */
KOF_DIAG_ANCHOR(r, KOF_NUCLEO_KPROBE_REG, 0);
