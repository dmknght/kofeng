#include <kofmod/heur.h>

/*
 * rootkit_lkm_00.c - a loadable kernel module that can hook, and nothing
 * more than that.
 *
 * THIS RULE REPORTS NOTHING. It makes no claim about the module and names no
 * family. What it does is ASK FOR THE PATHOGEN ANALYSIS - see
 * KOF_ENG_USE_PATHOGEN - on the one class of object where that analysis is
 * the only way to see anything, and where the cost is worth paying.
 *
 *
 * ---- WHAT A HOOK FORCES A MODULE TO IMPORT -----------------------------
 *
 * To hook anything, a module must obtain the address of something it did not
 * link against: a syscall table entry, or a function pointer inside a kernel
 * structure. The kernel does not export those addresses. There are exactly
 * two doors, and both are symbols the kernel provides:
 *
 *   kallsyms_lookup_name                exported until 5.7
 *   register_kprobe + unregister_kprobe after 5.7 - put a probe on the name,
 *                                       read kp.addr, take the probe away
 *
 * THE SECOND IS NOT AN ALTERNATIVE A ROOTKIT CHOSE. It is what is left after
 * the kernel stopped exporting the first, which is why it is an evasion that
 * cannot evade: a module needing an unexported address has no third way to
 * ask for one.
 *
 *
 * ---- WHAT IS DELIBERATELY NOT HERE -------------------------------------
 *
 * MAKING THE TARGET WRITABLE NEEDS NO SYMBOL. The syscall table is read-only
 * and a rootkit clears the write-protect bit with `mov cr0` - inline
 * assembly, no import, nothing to match. That is why the engine recognises it
 * through its own decoder instead, and why it cannot be a condition here.
 *
 * HIDING THE MODULE IS BEHAVIOUR, NOT HOOKING. list_del on THIS_MODULE->list
 * is what a rootkit does after it has hooked, and ordinary modules use the
 * same list helpers for their own lists.
 *
 * FTRACE IS A REAL SECOND FAMILY AND IS NOT CLAIMED. register_ftrace_function
 * with ftrace_set_filter_ip interposes without ever resolving an address, so
 * a module using it imports none of the names below. No sample in this tree
 * uses it, and a condition that has never fired on anything is a condition
 * that says it works.
 *
 * AND A MODULE THAT HARDCODES ADDRESSES imports nothing at all. It is built
 * against one System.map and breaks on every other kernel; what it does is
 * still visible, but through the cr0 write and the stores beside it, not
 * through this rule.
 *
 *
 * ---- WHERE IT LOOKS, AND WHY NOT THROUGH A SEARCH ----------------------
 *
 * THE UNDEFINED SYMBOLS, walked as parse facts - not a region searched for
 * text. The difference decides everything here: "register_kprobe" found in
 * the bytes is any occurrence of that text, a string in a log message or a
 * name left in .comment, while a record flagged UNDEFINED is the claim that
 * this object CALLS it and the loader will resolve it against the kernel.
 *
 * AND A HEURISTIC MAY NOT SEARCH A REGION AT ALL. dbloader.c states it: only
 * a detector's regions enter the union the scanner resolves, "so a region
 * either of them names must not make every object pay for resolving it".
 * MEASURED before that was read: a signature scoped to KOF_SCAN_SYM_IMP
 * matched both rootkits and this same rule, scoped the same way, matched
 * neither - the region was never resolved because no DETECTOR had asked for
 * it. kof_syms() is the accessor a heuristic is meant to use: a block the
 * host already built while parsing.
 *
 * ET_REL first, because elf.h already measured what it costs: REL alone takes
 * 7221 objects down to 60.
 */

KOF_TARGET_FORMAT(KOF_FMT_ELF);
KOF_TARGET_SUBTYPE(KOF_ELF_REL);
KOF_HEUR_PHASE(KOF_HEUR_EXAMINE);
KOF_HEUR_NAME("LkmHook");
KOF_HEUR_WANT(KOF_ENG_USE_PATHOGEN);

/*
 * THE UNDEFINED SYMBOLS, as a range the matcher resolves - kof_sym_extents
 * decides where that half of the block lies and the engine runs the search
 * over it. Walking the records here instead would be a second answer to a
 * question the engine already answers, and the note on kof_sym_extents says
 * what that costs: three callers once disagreed about whether a symbol was
 * present at all.
 */
KOF_TARGET_RANGE(imports, KOF_SCAN_SYM_IMP);

KOF_DEFINE_STR(s_kp_reg,   "register_kprobe",
	       KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(s_kp_unreg, "unregister_kprobe",
	       KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(s_cred_pre, "prepare_creds",
	       KOF_CASE_EXACT, KOF_WORD_FULLWORD);
KOF_DEFINE_STR(s_cred_com, "commit_creds",
	       KOF_CASE_EXACT, KOF_WORD_FULLWORD);

KOF_DEFINE_HEUR
{
	/*
	 * ALL FOUR, NOT EITHER PAIR.
	 *
	 * The two things an LKM rootkit cannot do without, and Diamorphine
	 * does both: it hooks - which needs the address of something the
	 * kernel never exported, and after 5.7 the only way to ask is to
	 * register a kprobe on the name, read the address it carries and
	 * unregister it - and it hands a process root, which means building
	 * a cred and installing it, for which the kernel offers no other
	 * pair of calls.
	 *
	 * BOTH HALVES OF EACH PAIR. A module that registers a probe and
	 * leaves it is tracing; one that registers and immediately takes it
	 * away wanted the address. A module that builds a cred and does not
	 * install it has changed nothing.
	 *
	 * EVERY ONE IS AN UNDEFINED SYMBOL, which is what makes this hard to
	 * evade: the loader resolves them against the kernel's export table
	 * by exact name, so they cannot be renamed and cannot be stripped.
	 * The names a rootkit CAN change are its own - diamorphine's
	 * __sys_call_table is a local variable that `strip` removes, and its
	 * kallsyms_lookup_name_ is a pointer the author renamed on purpose,
	 * with a comment in the source saying why.
	 *
	 * MEASURED over 900 clean kernel modules from this machine:
	 * register_kprobe 0, unregister_kprobe 0, commit_creds 0,
	 * prepare_creds 2 - and no module carrying all four.
	 *
	 * STRICTER THAN EITHER PAIR ALONE, on purpose, and it is worth
	 * saying what that costs: a rootkit that only hides, or only
	 * escalates, is not asked about at all. This is the gate on an
	 * expensive analysis rather than a detection, so a miss here is a
	 * file that goes unanalysed - which is the reason to widen it when a
	 * sample shows one half without the other, and not before.
	 *
	 * AND A PRE-5.7 BUILD WOULD NEED kallsyms_lookup_name BACK as an
	 * alternative to the kprobe pair. Both builds in this tree are after
	 * it, so that string has never matched anything here and is not
	 * carried on the strength of the source alone.
	 */
	if (kof_find_str_all(imports, s_kp_reg, s_kp_unreg,
			     s_cred_pre, s_cred_com))
		KOF_HEUR_ACT();
}
