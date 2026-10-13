/*
 * tests/sigs/syndromes/rootkit_00.c - a fixture: a sample that was a rootkit and
 * on which the giveroot disease fired. Here to make the machinery run - the
 * builder that reads these macros, the pack, the loader, the inference - not a
 * survey of anything.
 */

KOF_DECLARE_SYNDROME_TYPE(KOF_MALTYPE_ROOTKIT);
KOF_DECLARE_SYNDROME_HAS("kernel/giveroot");
