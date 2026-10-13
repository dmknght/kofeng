/*
 * analyzers/diseases/kofdisease.h - the word a diagnose's finding is
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

#ifndef KOFENG_DISEASES_KOFDISEASE_H
#define KOFENG_DISEASES_KOFDISEASE_H

#include <kofmod/kofdiagtree.h>   /* KOF_DIAG_DISEASE_LEN, the longest a disease may be */

#include <stddef.h>
#include <stdint.h>

/*
 * THE ID OF A DISEASE, FROM ITS NAME - what the engine and the packs carry
 * instead of the text. Written once here for the build that makes the records
 * and the engine that reads them, so the two cannot hash differently.
 *
 * 32 BITS AND NEVER ZERO (zero is "no disease"). A diagnose id is sixteen bits
 * because a database holds a few hundred; diseases are what many detectors
 * share and a database may hold thousands of words, and a collision here is a
 * different behaviour answering for another. The build refuses two names that
 * hash alike rather than hoping.
 *
 * The text is for a person: the db carries an id to name table (see
 * ksigbuilder's write_diseases) that a tool reads when it has to show one.
 */
uint32_t kof_disease_id(const char *name);

/*
 * NULL when `s` is a well-formed disease, otherwise what is wrong with it, as a
 * sentence a source reader can report: empty, longer than KOF_DIAG_DISEASE_LEN, a
 * character outside a-z 0-9 - _ /, or a path with an empty part (a leading,
 * trailing or doubled slash).
 */
const char *kof_disease_check(const char *s);

/*
 * ---- THE DECLARATION, READ AND WRITTEN -----------------------------------
 *
 * KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, "flood-network/raw-header") appears in
 * the source of every kind of detector, and three programs handle it: the build
 * that turns it into a record, the diagnose reader, and a tool that lets a person
 * change it. ONE parser and ONE printer, here, so what the build accepts is what
 * a tool shows and writes back - it was going to be three spellings of one rule.
 */
struct kof_disease_decl {
	uint8_t type;                           /* a kof_maltype */
	char    name[KOF_DIAG_DISEASE_LEN + 1u];
};

/*
 * Read the declaration whose macro name starts at `p`: the type, a comma, the
 * quoted name, the closing parenthesis, all on the text `p` points into (a line
 * with the comments already blanked, or the rest of the source).
 *
 * NULL when it was read, otherwise what is wrong, as a sentence the caller can
 * report with its own line number.
 */
const char *kof_disease_decl_parse(const char *p, struct kof_disease_decl *d);

/* The declaration as a line of source, without the newline; its length, or 0 when
 * `d` is not one that can be written (an unknown type, a name that is not a
 * well-formed disease). Cut and terminated at `cap`. */
size_t kof_disease_decl_print(const struct kof_disease_decl *d, char *out,
			      size_t cap);

/* Two declarations that say the same thing. */
int kof_disease_decl_same(const struct kof_disease_decl *a,
			  const struct kof_disease_decl *b);

#endif /* KOFENG_DISEASES_KOFDISEASE_H */
