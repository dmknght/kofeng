#include <kofmod/kofpathogen.h>

/*
 * kernel_kprobe-resolve_00.c - a kernel module obtaining the address of a kernel
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
 * ---- WHAT THIS SAYS ----------------------------------------------------
 *
 * The module ASKS THE KERNEL FOR A SYMBOL BY NAME through a probe: the node is
 * the resolver call, and the name handed to it is what a verdict reads with
 * kof_diag_str_any - `sys_call_table`, `x64_sys_call`. THAT is the evidence
 * about what is being reached.
 *
 * `kallsyms_lookup_name` is NOT that evidence. It is the probe's own
 * `symbol_name` - the variable that makes the kernel hand back an address -
 * and it is the same string in every build that uses the trick, so it says
 * "a probe resolver" and nothing about the target. It was asked for once, and
 * was the wrong question.
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

KOF_DIAG_NAME(DIAG_LKM_KPROBE_RESOLVE);

/*
 * BOTH ROUTES. SYMBOL finds the call; EMULATE is what reads the NAME the
 * probe was placed on out of the guest's memory and keeps it in the engine -
 * see capture_names. The names are read at the resolver node this diagnose
 * binds, and the analysis runs only the routes the diagnoses it is serving
 * declare.
 *
 * THIS WAS SYMBOL ALONE, on the reasoning that the call is all this claims.
 * Measured when a verdict first asked for the name: every condition was true
 * when forced through the engine's own calls and the verdict still did not
 * fire, because nothing had asked for the route that captures names, so the
 * store was empty and an empty store answers "not found". The cost is bounded
 * by the gate below - 0 of 900 clean modules import register_kprobe.
 */
KOF_DIAG_ANALYSIS(KOF_DIAG_ANALYSIS_SYMBOL | KOF_DIAG_ANALYSIS_EMULATE);

/*
 * ---- THE GATE: A RELOCATABLE OBJECT THAT IMPORTS THE PAIR ---------------
 *
 * 0 of 900 clean kernel modules import register_kprobe, so the analysis
 * never starts on one. Without a sign a diagnose runs on every kernel
 * module - measured once already, +47% on that corpus.
 */
KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);

/*
 * THE RESOLVER CALL IS THE HEAD. The engine places it where the
 * register/unregister pair lives (see the kprobe block in diag_emu.c), so it
 * exists only for a module that imports the pair - the sequence declared
 * below is what the head is made of, and the node is what carries the names
 * the caller passes.
 */
KOF_DIAG_DECLARE_HEAD(KOF_NUCLEO_KSYM_LOOKUP, 0);

/*
 * AND WHAT IT IS MADE OF: a probe put on, then taken off, in one function.
 * Said as a relationship because that is what it is - both being imported is
 * only the gate, and the gate is derived from this. No link between the two,
 * on purpose: hcrootkit takes the first probe down BEFORE it reads the
 * address, and a link would lose it.
 */
KOF_DIAG_DECLARE_SEQUENCE(KOF_NUCLEO_KPROBE_REG, KOF_NUCLEO_KPROBE_UNREG);
