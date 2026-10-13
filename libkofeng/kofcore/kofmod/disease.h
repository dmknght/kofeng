#ifndef KOFMOD_DISEASE_H
#define KOFMOD_DISEASE_H

/*
 * kofmod/disease.h - the declaration every kind of detector uses to say what its
 * match FINDS.
 *
 * Here and not in kofdiagtree.h or kofsig.h because it is written in a diagnose
 * (which includes the first), in a signature or a heuristic (which include the
 * second), and one fact has one carrier: both include this.
 */

/*
 * KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, "flood-network/raw-header") - what this
 * detector's match FINDS: a word for the behaviour, and the type of malware that
 * behaviour belongs to. The disease the test detects.
 *
 *     KOF_DECLARE_DISEASE(KOF_MALTYPE_BOTNET, "flood-network/raw-header");
 *
 * THE TYPE IS A kof_maltype, the one every verdict already names. A disease does
 * not get a vocabulary of its own for it: "what kind of malware does this
 * behaviour belong to" has one answer in this tree.
 *
 * ONE PER DETECTOR, and a path: the first part is the layer, the rest narrows it.
 * Written in a diagnose, a signature or a heuristic - every kind of detector -
 * and the same name in two of them is one disease, which fires when any of them
 * matches. A name has ONE type: the build refuses the same name declared with two.
 *
 * WHAT THE ENGINE CARRIES IS AN ID (see analyzers/diseases/kofdisease.h);
 * the text is kept in a table for the tools. A detector says what the code DOES;
 * which KIND of malware a set of diseases makes is read from verified samples (see
 * databases/pack/kofsyndrome.h), so a disease names a behaviour and
 * never a family or a verdict. Optional: a detector without one matches as before.
 */
#define KOF_DECLARE_DISEASE(type, name)

#endif /* KOFMOD_DISEASE_H */
