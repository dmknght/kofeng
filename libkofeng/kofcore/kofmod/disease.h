#ifndef KOFMOD_DISEASE_H
#define KOFMOD_DISEASE_H

/*
 * kofmod/disease.h - the declaration a diagnose uses to say what its match FINDS.
 *
 * What a TOOL offers a researcher to pick is not here: it is the tags of the tag
 * sources (databases/tagsrc.h).
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
 * ONE PER DIAGNOSE, and a path: the first part is the layer, the rest narrows it.
 * The same name in two diagnoses is one disease, which fires when any of them
 * matches. A name has ONE type: the build refuses the same name declared with two.
 *
 * WHAT THE ENGINE CARRIES IS AN ID (see analyzers/diseases/kofdisease.h);
 * the text is kept in a table for the tools. A diagnose says what the code DOES, so
 * a disease names a behaviour and never a family or a verdict; the verdict of an
 * object is named from the diseases it has (kof_verdict_make). Optional: a
 * diagnose without one can be asked for by a module and names nothing.
 */
#define KOF_DECLARE_DISEASE(type, name)

#endif /* KOFMOD_DISEASE_H */
