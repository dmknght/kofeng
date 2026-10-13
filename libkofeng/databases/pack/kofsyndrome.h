/*
 * databases/pack/kofsyndrome.h - what the diagnoses that matched say a
 * file IS, by type.
 *
 * THE WORDS, from medicine because the structure is the same. A diagnose is a
 * test: it matches what the CODE DOES. What it finds is a DISEASE, named by a
 * word for the behaviour ("cnc/recv-syscall", "flood-network/raw-header"). The
 * diseases that were found together on one sample are a SYNDROME, and what a
 * syndrome means is a TYPE of malware (kof_maltype). Matching says which diseases
 * the object has; this says what kind of malware a set of them makes.
 *
 * THE KIND, NOT THE FAMILY. A bot that floods with Mirai's routine and
 * exploits with Gafgyt's is both and neither, so the behaviour cannot name a
 * family; it can name a type (kof_maltype). The family is "Agent", what an AV
 * calls a thing it can type but not place.
 *
 * THE KNOWLEDGE IS EXEMPLARS, not rules: each is the set of diseases that
 * fired on a sample somebody verified, and the types that sample was. Nothing
 * lists combinations, so a combination nobody foresaw is read the same way as
 * any other, and a count of diseases is not special-cased: the query is a set.
 *
 * TWO RELATIONS, AND THEY ARE NOT THE SAME CLAIM.
 *
 *   COMPATIBLE  Q <= T(x)   the query is no more than an exemplar shows. A
 *                           disease that did NOT fire says nothing - a C&C that
 *                           was down - so the types of every compatible
 *                           exemplar are POSSIBLE, never proven.
 *   SUFFICIENT  T(x) <= Q   the query shows everything an exemplar shows. That
 *                           proves the exemplar's type only if the syndrome
 *                           DISCRIMINATES: every exemplar that shows at least
 *                           that syndrome has the type. MEASURED without the
 *                           condition: 25 of 278 verified samples were given a
 *                           second type - a Botnet syndrome that a Trojan also
 *                           shows (the two share those tags) proved nothing.
 *
 * The union of syndromes is deliberately NOT used: it would join diseases that
 * never appeared on one sample.
 *
 * NO WEIGHTS AND NO PRIOR. What this answers is a set, and what it cannot
 * decide it says (ambiguous, unresolved) instead of picking.
 */

#ifndef KOFENG_KOFSYNDROME_H
#define KOFENG_KOFSYNDROME_H

#include <stddef.h>
#include <stdint.h>

#include "../../kofcore/koftypes.h"     /* struct kof_synd_result */

/* One verified sample: the types it was (a mask of 1u << kof_maltype) and the
 * diseases that fired on it, as ids - see kofdisease.h. The text of a disease is
 * never seen here: the algorithm compares ids and a tool translates them. */
struct kof_synd_in {
	uint32_t        type_mask;
	uint32_t        n_dis;
	const uint32_t *dis;
};

struct kof_synd_set;

/*
 * Built once from the exemplars. An exemplar with no disease shows nothing
 * and is dropped. NULL on allocation failure; a set with no exemplar is valid
 * and answers every query as unresolved.
 */
struct kof_synd_set *kof_synd_build(const struct kof_synd_in *in, uint32_t n);
void kof_synd_free(struct kof_synd_set *);

uint32_t kof_synd_count(const struct kof_synd_set *);

/*
 * The i-th verified sample the set was built from: the types it was, and the
 * diseases that fired on it as ids, ascending. 1 and `*dis` valid for the life of
 * the set, or 0 past the end. For a tool that shows what the inference is read
 * against; the order is the order they were built in, minus the ones that showed
 * nothing.
 */
int kof_synd_get(const struct kof_synd_set *, uint32_t i, uint32_t *type_mask,
		 uint32_t *n_dis, const uint32_t **dis);


/*
 * What the diseases `dis[0..n)` make. Duplicates are one. A disease no
 * exemplar carries is counted in n_unknown and leaves no exemplar compatible:
 * a behaviour nobody has verified is not evidence for any type.
 *
 * 1 when an answer was computed, 0 for no evidence at all (n == 0) or on
 * allocation failure; `r` is zeroed either way.
 */
int kof_synd_infer(const struct kof_synd_set *, const uint32_t *dis,
		   uint32_t n, struct kof_synd_result *r);

/*
 * THE NAME, written to `out`; its length. The cases are exhaustive:
 *
 *   a type proven            Botnet:Agent        (two proven: Botnet+Exploit:Agent)
 *   one type left possible   Botnet:Agent.Predict
 *   several left possible    Ambiguous(Botnet,Miner)
 *   nothing                  Malware:Unresolved
 *
 * Unresolved is a statement about the NAME: a file that matched a diagnose is
 * detected whatever this says.
 *
 * EXPERIMENTAL, AND THE GRAMMAR ABOVE IS HARD-CODED. It is here so the inference
 * can be measured end to end, not because the engine should decide how a type
 * is spelled. The family word ("Agent"), the ".Predict" suffix, the "+" joining
 * two types and the "Ambiguous(...)" and "Unresolved" forms are all choices a
 * researcher has to be able to make and change.
 *
 * WHAT IT BECOMES: a declaration in the bases, the way a verdict already
 * declares its type and family (KOF_TARGET_NAME), so that a researcher adds or
 * changes how a set of types is named without touching the engine - including
 * the name of a combination nobody foresaw. Until then this is the one place the
 * naming is written, and nothing outside it may spell a name of its own.
 */
size_t kof_synd_name(const struct kof_synd_result *r, char *out, size_t cap);

#endif /* KOFENG_KOFSYNDROME_H */
