/*
 * kofmod/kofpathogen.h - A DIAGNOSE: what a program does, as a tree of nucleo
 * groups and the proven links between them.
 *
 * A diagnose NAMES NO FAMILY AND CARRIES NO VERDICT. It says "a region was
 * allocated writable and executable in one call, something filled it, and
 * control went into it" and stops there. Whether that is a Metasploit
 * stager, a beacon or a self-unpacking installer is a question for a
 * signature, which reads the diagnose result as a fact - see kof_diag.
 *
 * WHY SEPARATE FROM A SIGNATURE AT ALL. Two reasons, and both are about
 * what changes when:
 *
 *   - BEHAVIOUR IS SLOW. The shape above has been the same since the first
 *     runtime packer. A family name changes weekly. Keeping them in one
 *     file means the slow thing is rewritten every time the fast thing is.
 *   - ONE SHAPE, MANY FAMILIES. Embedding the shape in each family's rule
 *     is N copies of one piece of knowledge, and the copy that is not
 *     updated is the one that stops matching.
 *
 * SO IT IS A TREE, AND THE TREE IS THE RELATION. There are no edge records.
 * A node names its parent and says WHICH OF ITS OWN INPUTS came from that
 * parent - see `role`. Three fields carry what a general edge table would.
 *
 * THE TREE IS A PROVENANCE TREE AND NOT A SEQUENCE, which is the one thing
 * about it that reads wrong at first. In
 *
 *     p = mmap(RWX);  read(fd, p, n);  jmp p;
 *
 * `jmp` is NOT a child of `read` although it runs after it. Both take their
 * value from `mmap`, so both are children of `mmap`. That is what makes an
 * inserted node harmless: a `sleep` between the two is simply a node
 * nothing is matched against, and MEASURED - msfvenom's x86-64 stager has
 * exactly that sleep and matches with it there.
 *
 * WHAT IS DELIBERATELY ABSENT, because each was tried and cost more than it
 * bought:
 *
 *   - ORDER. Static order is LAYOUT order, not execution order - measured
 *     on a Watchbog sample where the walk read fork, wait, exec while the
 *     program runs fork, exec, wait: the compiler lays the parent's arm
 *     before the child's. Proving real order needs dominance, which needs a
 *     control-flow graph, which this does not build.
 *   - DISTANCE. A count of instructions between two nodes is the one part
 *     of a rule an author can evade by inserting one instruction.
 *   - A JOIN. Two trees sharing a node is not expressible here and is not
 *     meant to be: that is verdict logic and lives in a signature, over the
 *     nodes a match bound - see kof_diag_share.
 */

#ifndef KOFMOD_KOFPATHOGEN_H
#define KOFMOD_KOFPATHOGEN_H

#include <stdint.h>

#include "kofcap.h"

/*
 * WHICH ANALYSIS ROUTINE CAN SATISFY THIS DIAGNOSE, as a set.
 *
 * The two differ by a whole order of cost, so the engine must know which to
 * run before it runs anything:
 *
 *   SYMBOL   read the imports and compare names. NOT ONE INSTRUCTION is
 *            decoded.
 *   SYSCALL  a syscall is not in any symbol table. The code has to be
 *            scanned for the instruction, then decoded, then the number
 *            resolved out of a register.
 *
 * NOT DERIVABLE from the capabilities alone, which is why it is declared.
 * KOF_NUCLEO_ALLOC_EXEC is reachable BOTH ways - `mmap` on a static ELF,
 * `VirtualAlloc` on a PE - while a diagnose about LoadLibrary followed by
 * GetProcAddress has only the symbol route and one about raw shellcode has
 * only the syscall route. Declaring it both bounds the work and says what
 * the diagnose is about.
 */
#define KOF_DIAG_VIA_SYSCALL (1u << 0)
#define KOF_DIAG_VIA_SYMBOL  (1u << 1)
/*
 * RUN THE SPAN BETWEEN KNOWN SITES. The only route that resolves a value
 * through arithmetic the other two cannot follow, and the only one that sees
 * anything which is not a call: a field read out of a structure, a write
 * into one, a control-register move. Diamorphine's syscall table patch is
 * entirely made of those, so a diagnose about it has no other route.
 *
 * IT COSTS MORE THAN THE OTHER TWO and is asked for rather than assumed -
 * which is what every KOF_DIAG_VIA is for.
 */
#define KOF_DIAG_VIA_EMULATE (1u << 2)
/*
 * RESOLVE THE APIS THE PROGRAM FINDS FOR ITSELF. A PE that walks the loader
 * data has none of what it calls in its import table, and what stands for an
 * API in its code is a number only the program understands. This route is
 * the ANALYSIS that turns the number into a name, once per object, by letting
 * the program's own resolver run against the modelled loader - see
 * diag_apihash.c. It is asked for rather than assumed, like the others, and
 * it is the only route whose product is ALSO read by something that is not a
 * diagnose: see KOF_DIAG_SERVES.
 */
#define KOF_DIAG_VIA_APIHASH (1u << 3)

/*
 * ---- WHAT AN ANALYSIS RESULT IS USED FOR, BEYOND A VERDICT --------------
 *
 * A diagnose is read by verdicts, and a diagnose no verdict reads is not run -
 * see KDIG_SEC_USERS. An analysis whose answer is wanted by the ENGINE itself
 * has no verdict to name it, and without a declaration the first rule would
 * silently switch it off. KOF_DIAG_SERVES is that declaration: it says which
 * part of the object description this diagnose's route is there to complete.
 *
 *     KOF_DIAG_SERVES(KOF_SERVE_PE_SYMBOLS);
 *
 * KOF_SERVE_PE_SYMBOLS - the APIs a PE resolves for itself are added to its
 * symbol block as imports, so that everything that reads imports (a rule on
 * SYM_IMP, a KOF_DIAG_NEEDS sign, a similarity over symbols) sees the program
 * the way it would if the author had used the import table.
 */
#define KOF_SERVE_PE_SYMBOLS (1u << 0)

/*
 * WHICH INPUT OF THE CHILD CAME FROM THE PARENT.
 *
 * SEPARATE FROM KOF_FLOW_ROLE_*, which answers a different question - which
 * argument decides what the CALL ITSELF means, like mmap's prot or socket's
 * domain. Sharing the name would put two meanings on one word in a file
 * where both are in scope.
 *
 * A role and not an argument index, because the index differs between the
 * syscall and the import that mean the same thing, and a diagnose must not
 * have to know which route satisfied it.
 */
enum kof_diag_role {
	KOF_DIAG_ROLE_NONE = 0,  /* the anchor: nothing fed it            */
	KOF_DIAG_ROLE_BUFFER,    /* read/write/recv: the memory written   */
	KOF_DIAG_ROLE_TARGET,    /* an indirect jump or call: where it goes */
	KOF_DIAG_ROLE_FD,        /* read/connect/close: the descriptor    */
	KOF_DIAG_ROLE_PATH,      /* open/exec: the name                   */
	/*
	 * THE MEMORY READ FROM, as against BUFFER which is the memory
	 * WRITTEN. A call with one of each needs both words.
	 *
	 * copy_to_user(to, from, n) is the case, and it is not a corner one:
	 * a hooked getdents reads a directory listing in, edits it, and
	 * writes it back, so the pair shares TWO objects - the kernel buffer
	 * it edits in and the userspace buffer the caller asked it to fill.
	 * With one word for both, the two relations collapse: kof_diag_note_in
	 * refuses the second as a repeat of the first, and the one it keeps is
	 * whichever came first.
	 *
	 * That refusal is right for a LOOP - the same site reached twice has
	 * not found a second relation - and it was hiding this. A role has to
	 * be precise enough that no call has two inputs wearing one.
	 */
	KOF_DIAG_ROLE_SOURCE,
	KOF_DIAG_ROLE_COUNT
};

/*
 * THE `parent` OF THE ROOT. One tree, one root, and the root is the node
 * the engine starts from - see the note on the anchor below.
 *
 * NOT CALLED KOF_DIAG_ANCHOR, although that is what it marks: the word is
 * already the authoring macro a few screens down, and two meanings on one
 * name in one header is a compile error on the good day and a wrong value
 * on the bad one.
 */
#define KOF_DIAG_NO_PARENT 0xffu

/*
 * Bits in kof_diag_node.bits.
 *
 * BIT 0 WAS KOF_DIAG_B_TOUCH, the diagnose offering a node as a join point.
 * It is gone, and the reason is worth keeping: a diagnose describes ONE
 * behaviour's links, so which of its nodes happens to also belong to
 * another behaviour is not a fact about it. The join is asked for at the
 * verdict, which is the only place that knows which two behaviours are
 * being put together - see kof_diag_share, which now names the capability
 * the two must meet at.
 */

/*
 * WHICH KIND OF EDGE THE DIAGNOSE WILL ACCEPT - see enum kof_diag_kind.
 *
 * NEITHER BIT SET MEANS EITHER, and that is the default on purpose: most
 * relations are provenance, a diagnose that does not care should not have to
 * say so, and every pack built before these bits existed carries zero here
 * and goes on meaning what it meant.
 *
 * SAYING IT MATTERS WHERE THE ORDER IS THE BEHAVIOUR. A module that fills a
 * buffer from userspace and writes one back has two edges to the allocation
 * and both are provenance; what makes it a hooked syscall rather than an
 * ioctl handler is that the second copy holds the SAME object the first one
 * filled. That is the shared edge, and a diagnose that cannot demand it
 * cannot tell the two apart.
 */
#define KOF_DIAG_B_PRODUCED (1u << 1)
#define KOF_DIAG_B_SHARED   (1u << 2)

/*
 * THE NODE DEMANDS THE VALUE IT WROTE - see KOF_DIAG_WROTE and `val` below.
 *
 * A VALUE, WHICH THE NOTE ON ATTRIBUTES SAYS DOES NOT BELONG IN MATCHING -
 * and that note is about a value the AUTHOR chose, a path or an address. A
 * value the OPERATING SYSTEM fixes is the other thing entirely, and the
 * vocabulary already matches on one: a syscall number. Zero written into a
 * credential is root, on every architecture and every kernel, because that
 * is what uid 0 MEANS; it is not a constant anybody picked.
 *
 * WHY IT IS NEEDED AT ALL. Without it a credential diagnose can say "the
 * object prepare_creds returned was written into and then installed", and
 * nfsd does exactly that - it builds credentials to act for a remote user.
 * What separates the two is not the shape and not how rare the symbols are:
 * it is that one writes the remote user's ids and the other writes zero.
 * Matching on rarity proves a file resembles no clean file; matching on the
 * value proves what the file DOES.
 */
#define KOF_DIAG_B_VAL      (1u << 3)

/*
 * THE NODE'S OBJECT IS A FIELD OF A NAMED SYMBOL - see KOF_DIAG_FIELD_OF.
 *
 * A FIELD, which is the whole of the claim, not the symbol. A kernel module
 * hands THIS_MODULE to the kernel constantly - it is the handle every
 * registration takes - and that is an opaque pointer passed on. Reaching
 * INTO it is a different act: the fields of a module's own struct module are
 * the kernel's bookkeeping about it, and editing them is editing what the
 * kernel believes.
 *
 * MEASURED on 900 clean kernel modules from this machine: 2699 references to
 * __this_module and 2698 of them are offset zero, the handle. One driver
 * reads +0x18, its own name. No clean module reaches any other field. Both
 * Diamorphine builds and both hcrootkit builds do.
 *
 * It needs the relocation table, so it is answerable on a RELOCATABLE object
 * and nowhere else - an operand naming a symbol is a hole in a .ko, and the
 * name is in the relocation beside it.
 */
#define KOF_DIAG_B_FIELD_OF (1u << 4)

/*
 * ONE NODE. Eight bytes and then its attributes.
 *
 * `cap` IS A NUCLEO GROUP ID AND NEVER A SYSCALL NUMBER OR A NAME. That is
 * the single most important property of this record:
 *
 *   - a rule written against `proc-start` matches execve on Linux and
 *     CreateProcess on Windows, because the group is what both resolve to;
 *   - adding an alias to the vocabulary - __GI_dup2, NtAllocateVirtualMemory
 *     - makes every existing rule see it, with no rebuild of the rule.
 *
 * Store the number or the name instead and both properties are lost. The
 * engine expands the group through nucleo for the object's format and
 * architecture, and THAT is what it looks for.
 *
 * SO THE GROUP IDS MUST BE FROZEN. Adding a word to a group is free;
 * renumbering a group breaks every rule that named it. Same discipline the
 * SIM_IT ids and the engine ids are held to.
 */
struct kof_diag_node {
	uint16_t cap;            /* enum kof_flow_cap - a GROUP, see above  */
	uint16_t flags;          /* KOF_FLOWF_* the node must carry         */
	uint8_t  parent;         /* index, or KOF_DIAG_NO_PARENT               */
	uint8_t  role;           /* enum kof_diag_role - which input        */
	uint8_t  bits;           /* KOF_DIAG_B_*                            */
	uint8_t  attr_len;       /* bytes of attribute following            */
	/*
	 * attr[attr_len] follows ON THE WIRE, see the note on attributes
	 * below. It is a run of (kind, length, payload), and this build
	 * decodes the kinds it knows into the fields after this point - a
	 * reader that does not know a kind skips it by its length, which is
	 * the whole reason the run carries one.
	 */
	uint64_t val;            /* KDIG_ATTR_VALUE, when KOF_DIAG_B_VAL    */
	/* KDIG_ATTR_SYM, when KOF_DIAG_B_FIELD_OF. The engine's storage. */
	const char *sym;
};

/*
 * WHY THE ATTRIBUTE RUN CARRIES ITS OWN LENGTH rather than being a fixed
 * struct: so a pack built today still reads when a later build adds an
 * attribute kind. The same reason dbcore.h gives for keeping a plague
 * block's hashes in a second section rather than inside the block.
 *
 * WHAT BELONGS IN IT, and the line is the one the vocabulary already draws
 * between what the SYSTEM fixes and what the AUTHOR chose:
 *
 *   in   the CLASS of an argument - a path under a system directory, an
 *        executed program that is a shell. The class survives a variant
 *        renaming its dropper.
 *   out  the VALUE itself - "/usr/bin/mand", 185.10.68.100. That is
 *        evidence to report, not a thing to match on; matching it is
 *        pattern matching with extra steps.
 */

/*
 * THE ANCHOR MUST BE RARE, and this is a property a diagnose is responsible
 * for rather than one the engine can fix.
 *
 * Matching starts by finding every node in the object that could be the
 * root, and descends from each. A root of KOF_NUCLEO_ALLOC_EXEC costs one
 * descent - measured, zero clean binaries in 846 of /usr/bin allocate
 * writable-and-executable in one call. A root of KOF_NUCLEO_READ would cost
 * one descent per read, and a single 1.1 MB sample here holds 447 indirect
 * calls.
 *
 * The build warns when a diagnose anchors on a common group.
 */

/*
 * ---- THE OTHER KIND OF SIGN: WHAT THE FILE IS ---------------------------
 *
 * A symbol name is a sign an object carries in a table. Some behaviours
 * leave no symbol at all - a msfvenom stager is a few hundred bytes of
 * shellcode with no imports - and for those the sign is what the loader was
 * handed: the file's own declarations about itself.
 *
 * WHY A SIGN HAS TO EXIST AT ALL. A diagnose with none is tried on every
 * object its route applies to, so one stager rule turned the analysis on
 * for every ELF in the scan: measured, 954 binaries from /usr/bin went from
 * 1.94 s to 3.45 s for a question none of them could have answered yes to.
 * The demand gate only bounds cost if the demand itself is cheap to answer,
 * and these are header fields the parser has already read.
 *
 *
 * ---- THE ENGINE SUPPLIES THE FACT, THE DIAGNOSE STATES THE CONDITION ----
 *
 * These were a set of named bits - ENTRY_WX, NO_SECTIONS, ONE_LOAD - and
 * each one's MEANING was a few lines of C inside the engine. That put the
 * condition in the wrong place twice over: a diagnose could only ask what
 * somebody had already implemented, and asking anything new meant editing
 * the scanner. Worse, a bit like ONE_LOAD was a whole compound predicate
 * under one name, so what it actually demanded could not be read off the
 * diagnose that used it - and when one of its clauses turned out to be a
 * build detail rather than a behaviour, nothing in the declaration showed
 * that.
 *
 * So the engine publishes FACTS, each one a single question with a single
 * answer, and a diagnose writes the CONDITION:
 *
 *     KOF_DIAG_WHEN(KOF_FACT_MAP_PERM, KOF_PERM_W | KOF_PERM_X);
 *     KOF_DIAG_WHEN(KOF_FACT_SECTIONS, 0);
 *
 * ALL OF THEM MUST HOLD. A diagnose names the shape it is worth running
 * on, and a shape is one statement rather than a menu.
 *
 * A FACT THIS BUILD DOES NOT KNOW IS A REFUSAL, not an ignored line: a
 * condition silently dropped is a diagnose that runs on files its author
 * excluded.
 */
enum kof_diag_fact {
	KOF_FACT_NONE = 0,
	/*
	 * THE MAPPING THAT HOLDS THE ENTRY POINT has all of these
	 * permissions - KOF_PERM_*, and KOF_PE_PERM_* on a PE, which is the
	 * same three bits under that format's own names.
	 */
	KOF_FACT_ENTRY_PERM,
	/*
	 * SOME MAPPING has all of them, whether or not the entry is in it.
	 *
	 * The broader question and usually the right one: a payload does not
	 * have to START in the region it will write code into - a loader can
	 * enter at an ordinary R+X segment and keep the writable-executable
	 * one for what it decrypts. Counted here: 0 of 1056 binaries under
	 * /usr/bin declare a W+X mapping of any kind; 9 of 254 malware
	 * objects do. On PE the mapping is a section, which is where that
	 * format puts the same fact.
	 */
	KOF_FACT_MAP_PERM,
	/*
	 * HOW MANY SECTION HEADERS THE FILE DECLARES, so zero means a file
	 * with no section table at all.
	 *
	 * It survives as a sign because the W+X population is the one that
	 * will grow: as more malware ships a writable-executable mapping that
	 * fact alone stops separating, and having stripped the section table
	 * as well is the half that still does.
	 */
	KOF_FACT_SECTIONS,
	/*
	 * WHAT KIND OF OBJECT IT IS - KOF_ELF_REL and the rest. On Linux a
	 * relocatable object is a loadable kernel module and nothing else
	 * that ships, and the walk takes an entirely different path through
	 * one, because it has no PT_LOAD.
	 */
	KOF_FACT_OBJ_KIND,
	/*
	 * THE FORMAT, as KOF_FMT_*. A route that exists for one format - the
	 * analysis that names what a PE resolves for itself - says so here rather
	 * than being started on every object and returning at once.
	 */
	KOF_FACT_FORMAT,
	KOF_FACT_COUNT
};

/* How many conditions one diagnose may state. */
#define KOF_DIAG_MAX_WHEN 8u

struct kof_diag_when {
	uint16_t fact;          /* enum kof_diag_fact */
	uint64_t val;
};

/*
 * HOW MANY SIGNS A DIAGNOSE MAY DECLARE, and how long one may be. A sign is
 * a symbol name; the kernel's own are well under this.
 */
#define KOF_DIAG_MAX_NEED  8u
#define KOF_DIAG_NEED_LEN 48u

struct kof_diag {
	uint16_t              id;       /* assigned by the build            */
	uint8_t               via;      /* KOF_DIAG_VIA_*                   */
	uint8_t               n_node;
	const char           *name;     /* for a person, never matched on   */
	const struct kof_diag_node *node;

	/*
	 * ---- THE SIGN THAT SAYS THIS OBJECT IS WORTH THE ANALYSIS -------
	 *
	 * Undefined symbols the object must import before the analysis is
	 * run for this diagnose at all. Not a verdict and not evidence: an
	 * ANCHOR, which is a place to start looking from. It does not need
	 * to be clean - a false one costs the analysis and nothing else -
	 * and demanding that it be clean is asking the cheap test to do the
	 * expensive test's job.
	 *
	 * DECLARED HERE RATHER THAN IN A HEURISTIC RULE. A heuristic naming
	 * the same symbols was the filter before, which meant two modules
	 * and two executions for one decision, and the decision belongs to
	 * whoever is going to use the answer.
	 *
	 * Empty means no sign: the diagnose is tried wherever its route can
	 * run, which is what every diagnose written before this did.
	 */
	uint8_t               n_need;
	const char           *need[KOF_DIAG_MAX_NEED];

	/*
	 * THE CONDITIONS ON WHAT THE FILE IS - see enum kof_diag_fact. ANDED
	 * with the symbols above rather than ORed: both kinds of sign are
	 * necessary conditions for the analysis being worth its cost, and a
	 * diagnose that wanted either would be two diagnoses.
	 */
	uint8_t               n_when;
	struct kof_diag_when  when[KOF_DIAG_MAX_WHEN];
	/*
	 * HOW MANY VERDICTS READ IT, when the build said - see KDIG_SEC_USERS.
	 * `users_known` distinguishes "none" from "nobody wrote it down".
	 */
	uint8_t               users_known;
	uint8_t               n_users;
	/*
	 * SYMBOLS THE CODE MUST REFER INTO, at a non-zero offset - see
	 * KOF_DIAG_REFS. Strings live in the same store as `need`.
	 */
	uint8_t               n_ref;
	const char           *ref[KOF_DIAG_MAX_NEED];
	/*
	 * WHAT THE ENGINE ITSELF USES THIS DIAGNOSE'S ROUTE FOR, as
	 * KOF_SERVE_* - see KOF_DIAG_SERVES. Non-zero keeps the diagnose
	 * running when no verdict reads it.
	 */
	uint8_t               serves;
};

/*
 * HOW FAR A LINK WAS ESTABLISHED. Three answers and not two.
 *
 * `BROKEN` and `UNKNOWN` must not be folded together. One says the value
 * demonstrably came from somewhere else - the diagnose really does not
 * match. The other says the model lost the value, through arithmetic it
 * does not follow or a round trip through memory it cannot see. Folded,
 * an author who can make the engine lose track has made themselves
 * innocent; kept apart, the weak answer can be weighed by the layer above.
 */
enum kof_diag_link {
	KOF_DIAG_LINK_PROVEN = 0,
	KOF_DIAG_LINK_BROKEN,
	KOF_DIAG_LINK_UNKNOWN
};

/*
 * ---- WRITING ONE -----------------------------------------------------------
 *
 * A diagnose source is read as TEXT by the build, exactly as a signature's
 * declarations are. The macros expand to nothing: what they do is make the
 * declaration legal C so an editor and a compiler both accept the file,
 * while the thing that reads them is ksigbuilder.
 *
 *     KOF_DIAG_NAME(rwx_exec);
 *     KOF_DIAG_VIA(KOF_DIAG_VIA_SYSCALL | KOF_DIAG_VIA_SYMBOL);
 *
 *     KOF_DIAG_ANCHOR(a, KOF_NUCLEO_ALLOC_EXEC, KOF_FLOWF_WX);
 *     KOF_DIAG_FROM(r, a, KOF_NUCLEO_READ,     KOF_DIAG_ROLE_BUFFER);
 *     KOF_DIAG_FROM(x, a, KOF_NUCLEO_EXEC_REG, KOF_DIAG_ROLE_TARGET);
 *
 * THE CAPABILITY IS THE ENUMERATOR, never the display name in quotes.
 * KOF_NUCLEO_EXEC_REG is what kofcap.h declares and what the engine, the
 * modules and the graph records all carry; "exec-memory" is what a report
 * prints it as. Writing the rule in the display name made the vocabulary
 * two vocabularies, one per audience, and the build now refuses the quoted
 * form rather than keeping both readable.
 *
 * KOF_DIAG_FROM NAMES THE PARENT RATHER THAN NESTING, because C has no
 * shape that nests and still reads as a tree - and a parent written out is
 * a parent a reader can see without counting braces. `a` is the parent of
 * both, which is the provenance tree and not the order they run in.
 *
 * THERE IS NO KOF_DIAG_TOUCH. A diagnose does not declare where it may be
 * joined to another - see the note on kof_diag_node.bits.
 */
#define KOF_DIAG_NAME(id)
#define KOF_DIAG_VIA(mask)
#define KOF_DIAG_ANCHOR(label, cap, flags)
/*
 * KOF_DIAG_FROM takes an OPTIONAL FIFTH ARGUMENT, a kind:
 *
 *     KOF_DIAG_FROM(t, f, KOF_NUCLEO_COPY_TO_USER, KOF_DIAG_ROLE_SOURCE,
 *                   KOF_DIAG_B_SHARED);
 *
 * Left out, the edge may be either kind - which is what every diagnose
 * written before this meant and still means. The macro expands to nothing,
 * so both arities are legal C and ksigbuilder reads whichever is written.
 */
#define KOF_DIAG_FROM(...)
/*
 * KOF_DIAG_NEEDS("prepare_creds", "commit_creds") - the imports an object
 * must carry before this diagnose is worth running. See struct kof_diag.
 */
#define KOF_DIAG_NEEDS(...)
/*
 * KOF_DIAG_REFS("__this_module") - the object's code must contain an
 * instruction whose operand is a relocation against this symbol at an
 * OFFSET OTHER THAN ZERO: it takes the address of something INSIDE it, not
 * the symbol itself. A sign like KOF_DIAG_NEEDS, and for the same reason - a
 * file-level condition, answered from a table, that decides whether the
 * expensive analysis starts at all - but about a different table: NEEDS asks
 * what the object IMPORTS, this asks what its instructions REFER TO.
 *
 * WHY IT IS A DECLARATION AND NOT SOMETHING THE ENGINE KNOWS. The engine has
 * no idea that __this_module matters; it has one question it can answer -
 * does a code relocation name this symbol at a non-zero addend - and the
 * diagnose says which symbol. The same question serves any symbol whose
 * fields, rather than whose address, are the interesting thing.
 *
 * A symbol with no OFFSET to speak of is a different question and this does
 * not answer it: a reference at offset zero is the handle, and a module
 * hands THIS_MODULE to the kernel constantly.
 *
 * ONE LINE PER CALL, as KOF_DIAG_NEEDS and KOF_DIAG_WHEN.
 */
#define KOF_DIAG_REFS(...)
/*
 * KOF_DIAG_WROTE(label, 0) - the node must have written this value.
 *
 * Only for a node that writes. See KOF_DIAG_B_VAL for why a value may be
 * matched on at all, and for the one kind that may: a value the operating
 * system fixes the meaning of.
 */
#define KOF_DIAG_WROTE(label, value)
/*
 * KOF_DIAG_FIELD_OF(d, "__this_module") - an argument of this node is the
 * address of a FIELD of that symbol, not the symbol itself. See
 * KOF_DIAG_B_FIELD_OF.
 */
#define KOF_DIAG_FIELD_OF(label, name)
/*
 * KOF_DIAG_WHEN(KOF_FACT_SECTIONS, 0) - a condition on what the file IS,
 * which is what decides whether the analysis runs on it at all. The engine
 * publishes the facts - see enum kof_diag_fact - and this is where a
 * diagnose states what it wants them to be.
 *
 * ONE LINE PER CALL, and repeat the macro for more than one condition. The
 * build reads these declarations a LINE at a time, so a value wrapped onto
 * a second line loses everything after the break - silently, because what
 * is left is still legal. KOF_DIAG_NEEDS is written the same way for the
 * same reason.
 */
#define KOF_DIAG_WHEN(fact, value)
/* KOF_DIAG_SERVES(KOF_SERVE_PE_SYMBOLS) - see the block above KOF_SERVE_*. */
#define KOF_DIAG_SERVES(mask)

/*
 * A TAGGED TRAILING SECTION OF A .kdig, tag then one length byte.
 *
 * HERE BECAUSE THE BUILD AND THE ENGINE ARE THE TWO ENDS OF THIS FILE, and
 * this header is the one they both read - the same reason the graph record
 * offsets below are here rather than inside the engine.
 *
 * Everything before these is positional - the nodes, then the signs - which
 * is why anything added later carries a length: a reader built before the
 * section exists skips it instead of mistaking it for the next thing it
 * does know.
 */
#define KDIG_SEC_WHEN  2u      /* (fact u16, value u64) pairs */
/*
 * WHICH VERDICTS READ THIS DIAGNOSE. A count, then the names of the
 * signatures that call it (a length byte and the bytes, as many as fit).
 *
 * WRITTEN BY THE BUILD AND NEVER BY AN AUTHOR. A signature already says
 * which diagnose it reads, in the one place that cannot drift from what it
 * does - the call - so a second statement of it, in the verdict or beside the
 * diagnose, would be a fact with two carriers. The build reads the calls out
 * of the signature sources and records the result here.
 *
 * WHAT THE ENGINE DOES WITH IT: a diagnose no verdict reads is not run. It
 * still gates and still starts the analysis, otherwise - measured, three
 * diagnoses nothing called cost the kernel-module corpus 1.05 s on a
 * baseline of 1.48 s, to compute answers nobody asked for.
 *
 * ABSENT MEANS UNKNOWN, NOT NONE. A .kdig written before this existed has no
 * section and must keep running; only a count of ZERO says nobody reads it.
 */
#define KDIG_SEC_USERS 3u
/*
 * SYMBOLS THE OBJECT'S CODE MUST REFER INTO - a count, then each name as a
 * length byte and the bytes. See KOF_DIAG_REFS.
 */
#define KDIG_SEC_REFS  4u
/* KOF_SERVE_* - one byte. See KOF_DIAG_SERVES. */
#define KDIG_SEC_SERVES 5u

/*
 * AND A TAGGED ATTRIBUTE OF ONE NODE, inside that node's attr run: kind,
 * then one length byte, then the payload. Same shape and same reason as the
 * sections above.
 */
#define KDIG_ATTR_VALUE 1u      /* 8 bytes LE - the value the node wrote */
#define KDIG_ATTR_SYM   2u      /* a symbol name, not terminated         */


/*
 * ==== WHAT THE ANALYSIS PRODUCED, AS A RULE READS IT =======================
 *
 * Everything above declares what to LOOK FOR. What the analysis hands back is
 * a graph - nodes, and the relations between them - and a verdict is an
 * algorithm over that graph, written in a rule where the family name already
 * lives.
 *
 * ONE HEADER, because they are one subsystem seen from its two ends, and
 * because two headers meant two spellings of the same facts: the roles and
 * the kinds below were written twice, with a compile-time assert holding them
 * level. A fact kept in two places drifts, and the assert was the admission.
 *
 * A BLOCK OF RECORDS, NOT THE ENGINE'S STRUCT, for the reason kofsym.h gives
 * about symbols: handing a module an internal struct makes its layout an ABI
 * nobody declared. Byte offsets are declared, and a field added later does not
 * move the ones a shipped module already reads.
 */

/*
 * The block: one header, then `count` records of KOF_GR_RECLEN bytes.
 * Little endian, like every other number the pack writes.
 */
/*
 * WHAT ONE OBJECT'S GRAPH MAY TAKE. Nothing is pruned - a verdict reads
 * nodes no diagnose names, so there is no set to prune to - and the bound is
 * therefore the OBJECT's: 4096 nodes, which the walk's own DIAG_MAX_NODE
 * stops at first. What keeps a 40 MB binary from paying for this is not
 * being asked about at all, see KOF_ENG_USE_PATHOGEN.
 */
#define KOF_GR_MAX_BYTES (8u + 4096u * 32u)

#define KOF_GR_HDRLEN   8u
#define KOF_GR_H_COUNT  0u      /* 4  how many records follow */
#define KOF_GR_H_RESV   4u      /* 4  zero                    */

/*
 * A NODE. `at` is an offset into the object, and KOF_DIAG_BROKEN_AT means the
 * site is not in the file at all - code the run produced.
 *
 * `attr` is a structure displacement. It used to be the offset of a name as
 * well, flagged by a bit in the byte below; names are kept in the engine now
 * and read through kof_diag_str, so the field means one thing.
 */
#define KOF_GR_RECLEN   32u
#define KOF_GR_R_AT      0u     /* 8  offset of the site                    */
#define KOF_GR_R_ATTR    8u     /* 8  displacement                          */
#define KOF_GR_R_CAP    16u     /* 2  enum kof_flow_cap                     */
#define KOF_GR_R_FLAGS  18u     /* 2  KOF_FLOWF_* seen here                 */
#define KOF_GR_R_BITS   20u     /* 1  KOF_GR_B_*                            */
#define KOF_GR_R_NIN    21u     /* 1  how many of the four links are used   */
/*
 * The links in, four of them, two bytes each: the parent's RECORD INDEX, then
 * the role, then the kind. A parent of 0xffff is none; 0xfffe is the stack
 * region, which is a place rather than a node.
 */
#define KOF_GR_R_IN     22u     /* 4 x (2 from, 1 role, 1 kind) = 10 bytes  */
#define KOF_GR_IN_STRIDE 4u
#define KOF_GR_IN_MAX    4u
#define KOF_GR_FROM_NONE  0xffffu
#define KOF_GR_FROM_STACK 0xfffeu

/* The bits byte is reserved and zero. Bit 0 was KOF_GR_B_ATTR_STR; the
 * number is left unused so nothing built against it reads another meaning. */


static inline uint32_t kof_gr_count(const uint8_t *b, uint32_t n)
{
	if (!b || n < KOF_GR_HDRLEN)
		return 0;
	return (uint32_t)b[KOF_GR_H_COUNT] |
	       ((uint32_t)b[KOF_GR_H_COUNT + 1] << 8) |
	       ((uint32_t)b[KOF_GR_H_COUNT + 2] << 16) |
	       ((uint32_t)b[KOF_GR_H_COUNT + 3] << 24);
}

static inline const uint8_t *kof_gr_rec(const uint8_t *b, uint32_t n,
					uint32_t i)
{
	uint64_t at = (uint64_t)KOF_GR_HDRLEN + (uint64_t)i * KOF_GR_RECLEN;

	if (i >= kof_gr_count(b, n) || at + KOF_GR_RECLEN > (uint64_t)n)
		return 0;
	return b + at;
}

static inline uint64_t kof_gr_u64(const uint8_t *r, uint32_t at)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < 8u; i++)
		v |= (uint64_t)r[at + i] << (i * 8u);
	return v;
}

static inline uint16_t kof_gr_u16(const uint8_t *r, uint32_t at)
{
	return (uint16_t)((uint16_t)r[at] | ((uint16_t)r[at + 1u] << 8));
}

/* One link of a node: its parent's index, the role it fills and which
 * relation it is. Answers KOF_GR_FROM_NONE past the last one. */
static inline uint16_t kof_gr_in(const uint8_t *r, unsigned k,
				 uint8_t *role, uint8_t *kind)
{
	const uint8_t *p;

	if (k >= KOF_GR_IN_MAX || k >= r[KOF_GR_R_NIN])
		return KOF_GR_FROM_NONE;
	p = r + KOF_GR_R_IN + k * KOF_GR_IN_STRIDE;
	if (role)
		*role = p[2];
	if (kind)
		*kind = p[3];
	return kof_gr_u16(p, 0);
}

/*
 * ---- ASKING THE GRAPH, ONCE -------------------------------------------
 *
 * Two rules walked these records by hand before this existed and both
 * wrote the same loop: step every record, read the capability, remember
 * what was seen. A third would have written it again, and the one that got
 * it subtly wrong would have been the one nobody noticed - which is what
 * the note on kof_sym_extents says happened to symbol lookups.
 *
 * WHAT A VERDICT ACTUALLY ASKS, from the two that exist:
 *
 *   IS IT THERE          a socket was opened; the write-protect bit came
 *                        down. Nodes that are nobody's child, which is
 *                        exactly what a diagnose tree cannot reach.
 *   HOW MANY DIFFERENT   three entries of one object written, not one
 *                        field of it written three times.
 *
 * Neither is a tree. Both are counting, and counting is why a verdict is
 * an algorithm rather than another declaration.
 */

/*
 * IS THERE AN EDGE: a node of `child_cap` whose parent is a node of
 * `parent_cap`, filling `role`.
 *
 * The question a verdict asks most, and the one it cannot ask by counting:
 * "the region that was jumped into is the region that was allocated" is an
 * edge, not a tally. `flags` must all be present on the PARENT - pass 0 to
 * ask about any - which is how a verdict says W+X without a second call.
 */
static inline int kof_gr_linked(const uint8_t *b, uint32_t n,
				uint16_t parent_cap, uint16_t child_cap,
				uint8_t role, uint16_t flags)
{
	const uint8_t *r;
	uint32_t i;

	for (i = 0; (r = kof_gr_rec(b, n, i)) != 0; i++) {
		unsigned k;

		if (kof_gr_u16(r, KOF_GR_R_CAP) != child_cap)
			continue;
		for (k = 0; k < KOF_GR_IN_MAX; k++) {
			uint8_t ro = 0, kind = 0;
			uint16_t from = kof_gr_in(r, k, &ro, &kind);
			const uint8_t *p;

			if (from >= KOF_GR_FROM_STACK || ro != role)
				continue;
			p = kof_gr_rec(b, n, from);
			if (!p || kof_gr_u16(p, KOF_GR_R_CAP) != parent_cap)
				continue;
			if ((kof_gr_u16(p, KOF_GR_R_FLAGS) & flags) != flags)
				continue;
			return 1;
		}
	}
	return 0;
}

/* Is there a node with this capability. */
static inline int kof_gr_has(const uint8_t *b, uint32_t n, uint16_t cap)
{
	const uint8_t *r;
	uint32_t i;

	for (i = 0; (r = kof_gr_rec(b, n, i)) != 0; i++)
		if (kof_gr_u16(r, KOF_GR_R_CAP) == cap)
			return 1;
	return 0;
}

/*
 * HOW MANY DISTINCT `attr` VALUES among nodes of `child_cap` whose parent
 * is a node of `parent_cap` in `role`.
 *
 * DISTINCT, because the question is how much of one object was touched:
 * three stores into one field is a module updating a counter, and three
 * stores into three entries is a table being rewritten. Only `attr` tells
 * them apart.
 *
 * `cap_max` bounds the answer, not the search - a caller asking "at least
 * three" does not need to know it was nine.
 */
static inline uint32_t kof_gr_entries(const uint8_t *b, uint32_t n,
				      uint16_t parent_cap, uint16_t child_cap,
				      uint8_t role, uint32_t cap_max)
{
	uint64_t seen[16];
	uint32_t n_seen = 0, i;
	const uint8_t *r;

	if (cap_max > (uint32_t)(sizeof seen / sizeof seen[0]))
		cap_max = (uint32_t)(sizeof seen / sizeof seen[0]);
	for (i = 0; (r = kof_gr_rec(b, n, i)) != 0 && n_seen < cap_max; i++) {
		uint64_t at;
		unsigned k;

		if (kof_gr_u16(r, KOF_GR_R_CAP) != child_cap)
			continue;
		at = kof_gr_u64(r, KOF_GR_R_ATTR);
		if (!at)
			continue;
		for (k = 0; k < KOF_GR_IN_MAX; k++) {
			uint8_t ro = 0, kind = 0;
			uint16_t from = kof_gr_in(r, k, &ro, &kind);
			const uint8_t *p;
			uint32_t t;

			if (from >= KOF_GR_FROM_STACK || ro != role)
				continue;
			p = kof_gr_rec(b, n, from);
			if (!p || kof_gr_u16(p, KOF_GR_R_CAP) != parent_cap)
				continue;
			for (t = 0; t < n_seen; t++)
				if (seen[t] == at)
					break;
			if (t == n_seen && n_seen < cap_max)
				seen[n_seen++] = at;
			break;
		}
	}
	return n_seen;
}


#endif /* KOFMOD_KOFPATHOGEN_H */
