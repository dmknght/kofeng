/*
 * detectors/pathogen/diseases/kofdisease.h - the word a diagnose's finding is
 * named by.
 *
 * A diagnose is a test; what it finds is a DISEASE, written as a path of
 * lower-case words: the layer first, then what narrows it
 * ("flood-network/raw-header"). Syndromes (../syndrome) are sets of these, read
 * against verified samples, so the spelling is compared BYTE FOR BYTE in three
 * places - the diagnose that carries it, the syndrome that names it, and the
 * engine that matches the two. A spelling that differs by case or a stray slash
 * would be a different behaviour that nothing carries, so ONE function decides
 * what a well-formed disease is, and every reader asks it.
 *
 * It used to be written twice - once in the diagnose reader and once in the
 * syndrome reader - and the two had already drifted by one rule.
 */

#ifndef KOFENG_PATHOGEN_KOFDISEASE_H
#define KOFENG_PATHOGEN_KOFDISEASE_H

#include <kofmod/kofpathogen.h>   /* KOF_DIAG_DISEASE_LEN, the longest a disease may be */

/*
 * NULL when `s` is a well-formed disease, otherwise what is wrong with it, as a
 * sentence a source reader can report: empty, longer than KOF_DIAG_DISEASE_LEN, a
 * character outside a-z 0-9 - _ /, or a path with an empty part (a leading,
 * trailing or doubled slash).
 */
const char *kof_disease_check(const char *s);

#endif /* KOFENG_PATHOGEN_KOFDISEASE_H */
