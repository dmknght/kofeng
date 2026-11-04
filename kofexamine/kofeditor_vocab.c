#define _GNU_SOURCE

/*
 * kofeditor_vocab.c - the vocabularies the panel offers: architectures, subtypes, malware types, each generated from the engine's list so a menu cannot offer what the builder rejects.
 *
 * A part of the diagnose panel's draft model (see kofeditor.h for why it is apart from
 * the viewer); the types and what the parts share are in kofeditor_private.h.
 * Moved verbatim from kofeditor.c.
 */

#include "kofeditor_private.h"






/*
 * The architectures to offer, generated from the engine's list.
 *
 * The word here is the identifier with KOF_ARCH_ cut off, because that is what
 * the panel shows and what the emitted KOF_TARGET_ARCH() is built back up from.
 * Generated rather than typed so the menu cannot offer an architecture the
 * builder will reject, or miss one it would accept - which it did, three of
 * them, while this was a hand written list.
 */
#define ARCH_X_WORD(name, val, short_word) { &#name[sizeof "KOF_ARCH_" - 1], val },
const struct kof_arch_word arch_word[] = { KOF_ARCH_LIST(ARCH_X_WORD) };
#undef ARCH_X_WORD

/* Both generated from the format headers, for the reason arch_word is: the menu
 * must offer exactly what the builder accepts. The prefix is cut off because
 * the panel shows the bare kind and the emitted declaration puts it back. */
#define ELF_SUB_X(name, val) &#name[sizeof "KOF_ELF_" - 1],
const char *const elf_sub[] = { KOF_ELF_TYPE_LIST(ELF_SUB_X) };
#undef ELF_SUB_X

#define PE_SUB_X(name, val) &#name[sizeof "KOF_PE_" - 1],
const char *const pe_sub[]  = { KOF_PE_IMAGE_LIST(PE_SUB_X) };
#undef PE_SUB_X

/*
 * AND THE SCRIPT KINDS, WHICH THE GENERATOR HAD NO NAMES FOR.
 *
 * KOF_TARGET_SUBTYPE was written for ELF and for PE and for nothing else, so a
 * draft that declared a script kind had it DROPPED from the source - the panel
 * said the rule was about php and the file written did not say so. Silent, and
 * the same shape as the format list that stopped at KOF_FMT_PDF.
 *
 * From KOF_SCRIPT_TYPE_LIST, like the two above come from theirs, so a kind
 * added to that list is a name here without anyone remembering to add it.
 */
#define SCRIPT_SUB_X(name, val) &#name[sizeof "KOF_SCRIPT_" - 1],
const char *const script_sub[] = { KOF_SCRIPT_TYPE_LIST(SCRIPT_SUB_X) };
#undef SCRIPT_SUB_X
const uint32_t script_sub_n = sizeof script_sub / sizeof script_sub[0];

/*
 * AND THE PLATFORM A PROCESS RECORD IS FROM, on the same axis for the same
 * reason - see KOF_PROC_OS_LIST. A command line is not one language, and a
 * rule about `cmd /c` has no business being offered a bash start.
 */
#define PROC_SUB_X(name, val) &#name[sizeof "KOF_PROC_OS_" - 1],
const char *const proc_sub[] = { KOF_PROC_OS_LIST(PROC_SUB_X) };
#undef PROC_SUB_X
const uint32_t proc_sub_n = sizeof proc_sub / sizeof proc_sub[0];



/* The subtypes, per format. The values overlap between formats, which is why
 * naming one format's values while targeting another is a build error. */


/*
 * One line: how many modules this object touched, and which one the hex pane is
 * lighting up. The rest is one keypress or one click away.
 */
/*
 * The bottom line: what is known about this object on the left, what is under
 * the cursor on the right.
 *
 * They used to be the same space, so making a selection erased the marker
 * counts - the two things a reader compares while choosing bytes. They are
 * different questions with different lifetimes and they get different halves.
 *
 * The pane indicator is gone. It named the thing with the keyboard focus, which
 * the caret in that pane already says, and it was the first thing on the line
 * that nobody needed.
 */
/*
 * The draft, as it stands.
 *
 * Grouped visually by region rather than sorted, because the order markers were
 * chosen in is information - it is the order somebody read the object - and a
 * signature's declarations do not care about order at all.
 */
/* The display words, from the engine's list. The menu offers exactly the types
 * a diagnose may declare. */
#define MALTYPE_X_WORD(name, word) word,
const char *const maltype_word[] = { KOF_MALTYPE_LIST(MALTYPE_X_WORD) };
#undef MALTYPE_X_WORD

/*
 * The counts, computed where the tables are.
 *
 * They were macros in the header, and a macro cannot count an array it cannot
 * see: the declaration had to carry a hand-written size, which made sizeof in
 * the assert meaningless and let a wrong number through as an "excess elements"
 * warning instead of an error. A variable filled by sizeof at the definition
 * cannot be wrong.
 */
const uint32_t arch_n         = sizeof arch_word     / sizeof arch_word[0];
const uint32_t elf_sub_n      = sizeof elf_sub       / sizeof elf_sub[0];
const uint32_t pe_sub_n       = sizeof pe_sub        / sizeof pe_sub[0];
/* Every target value the engine has - see fmt_word above. */
const uint32_t fmt_word_n     = KOF_TARGET_COUNT;
const uint32_t maltype_word_n = sizeof maltype_word  / sizeof maltype_word[0];
