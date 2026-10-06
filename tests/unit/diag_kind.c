/*
 * diag_kind - the two relations a link can be, kept apart.
 *
 * WHAT THIS IS FOR. The model used to have one kind of edge: the parent
 * returned the value the child's input holds. A second relation was being
 * recorded through it - two calls handed the SAME object, neither of which
 * made it - and with one word for both, a node reached by both came out with
 * two parents wearing one role. The engine then had to choose one, and what
 * it chose was wrong half the time: a RECEIVER recorded as the producer of a
 * buffer something else had produced.
 *
 * WHY IT IS NOT COSMETIC. A kernel module that allocates a buffer, fills it
 * from userspace, edits it and copies it back is
 *
 *     kzalloc -> copy_from_user -> (edit) -> copy_to_user
 *
 * and BOTH copies genuinely hold what kzalloc produced. What makes it a
 * hooked system call rather than an ordinary handler is the third statement:
 * copy_to_user holds the same object copy_from_user filled. Measured on 900
 * clean kernel modules from this machine, the alloc-and-two-copies shape
 * alone appears in 17 of them - so the shape is not the evidence and the
 * ordering is.
 *
 * SO BOTH EDGES MUST SURVIVE, and a diagnose must be able to demand which it
 * means. Three cases below, and the third is the one that fails if the kinds
 * are folded back together.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofpathogen.h"
#include "../../libkofeng/detectors/pathogen/kofdiag.h"
#include "../../libkofeng/detectors/pathogen/diag_int.h"

static int fails;

#define CK(x) do { if (!(x)) { \
	printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #x); fails++; } \
	} while (0)

int main(void)
{
	struct kof_diag_hit hits[4];
	struct kof_diag_scan s;
	struct kof_diag_hit *h;

	memset(hits, 0, sizeof hits);
	memset(&s, 0, sizeof s);
	s.hit = hits;
	s.cap_hit = 4u;

	/* the three nodes of a hooked getdents, built by hand so the test
	 * states the shape rather than depending on a sample to contain it */
	CK(kof_diag_hit_add(&s, 0x10, KOF_NUCLEO_HEAP, 0) != NULL);
	CK(kof_diag_hit_add(&s, 0x20, KOF_NUCLEO_COPY_FROM_USER, 0) != NULL);
	CK(kof_diag_hit_add(&s, 0x30, KOF_NUCLEO_COPY_TO_USER, 0) != NULL);
	CK(s.n_hit == 3u);

	h = kof_diag_hit_of(&s, 1u);
	CK(h != NULL);
	if (h)
		kof_diag_note_in(h, 0u, KOF_DIAG_ROLE_BUFFER,
				 KOF_DIAG_KIND_PRODUCED);

	h = kof_diag_hit_of(&s, 2u);
	CK(h != NULL);
	if (h) {
		kof_diag_note_in(h, 0u, KOF_DIAG_ROLE_SOURCE,
				 KOF_DIAG_KIND_PRODUCED);
		kof_diag_note_in(h, 1u, KOF_DIAG_ROLE_SOURCE,
				 KOF_DIAG_KIND_SHARED);
	}

	/*
	 * ONE: BOTH EDGES ARE THERE, and the roles are the same word. This is
	 * the shape the model could not hold - not because the dedup refused
	 * it, these two have different parents, but because the routine that
	 * builds them kept ONE entry per value and so only ever offered one
	 * of the two. What the count checks is that nothing downstream of
	 * that throws the second away.
	 */
	CK(h && h->n_in == 2u);

	/* and a repeat of either IS refused - the loop case the dedup exists
	 * for, which must survive the key growing a third field */
	if (h) {
		kof_diag_note_in(h, 1u, KOF_DIAG_ROLE_SOURCE,
				 KOF_DIAG_KIND_SHARED);
		CK(h->n_in == 2u);
	}

	/*
	 * TWO: A DIAGNOSE THAT NAMES NO KIND ACCEPTS EITHER. Every diagnose
	 * written before the kinds existed is this one, and must go on
	 * meaning what it meant.
	 */
	{
		static const struct kof_diag_node nd[] = {
			{ KOF_NUCLEO_COPY_FROM_USER, 0, KOF_DIAG_NO_PARENT,
			  KOF_DIAG_ROLE_NONE, 0, 0 },
			{ KOF_NUCLEO_COPY_TO_USER, 0, 0, KOF_DIAG_ROLE_SOURCE,
			  0, 0 },
		};
		static const struct kof_diag dg = {
			1, KOF_DIAG_VIA_SYMBOL, 2, "either", nd
		};

		CK(kof_diag_match(&s, &dg, NULL, NULL) == 1);
	}

	/*
	 * THREE: THE SHARED EDGE CAN BE DEMANDED, AND THE PRODUCED ONE
	 * CANNOT SATISFY IT.
	 *
	 * copy_to_user IS linked to copy_from_user, and it is also linked to
	 * the allocation - so a matcher that ignored the kind would answer
	 * yes to both of these. The pair is the test: the first must match
	 * and the second must not.
	 */
	{
		static const struct kof_diag_node yes[] = {
			{ KOF_NUCLEO_COPY_FROM_USER, 0, KOF_DIAG_NO_PARENT,
			  KOF_DIAG_ROLE_NONE, 0, 0 },
			{ KOF_NUCLEO_COPY_TO_USER, 0, 0, KOF_DIAG_ROLE_SOURCE,
			  KOF_DIAG_B_SHARED, 0 },
		};
		static const struct kof_diag_node no[] = {
			{ KOF_NUCLEO_COPY_FROM_USER, 0, KOF_DIAG_NO_PARENT,
			  KOF_DIAG_ROLE_NONE, 0, 0 },
			{ KOF_NUCLEO_COPY_TO_USER, 0, 0, KOF_DIAG_ROLE_SOURCE,
			  KOF_DIAG_B_PRODUCED, 0 },
		};
		static const struct kof_diag dyes = {
			1, KOF_DIAG_VIA_SYMBOL, 2, "shared", yes
		};
		static const struct kof_diag dno = {
			1, KOF_DIAG_VIA_SYMBOL, 2, "produced", no
		};

		CK(kof_diag_match(&s, &dyes, NULL, NULL) == 1);
		CK(kof_diag_match(&s, &dno, NULL, NULL) == 0);
	}

	/* and the allocation's edge is provenance, from the other side */
	{
		static const struct kof_diag_node nd[] = {
			{ KOF_NUCLEO_HEAP, 0, KOF_DIAG_NO_PARENT,
			  KOF_DIAG_ROLE_NONE, 0, 0 },
			{ KOF_NUCLEO_COPY_TO_USER, 0, 0, KOF_DIAG_ROLE_SOURCE,
			  KOF_DIAG_B_PRODUCED, 0 },
		};
		static const struct kof_diag dg = {
			1, KOF_DIAG_VIA_SYMBOL, 2, "from-alloc", nd
		};

		CK(kof_diag_match(&s, &dg, NULL, NULL) == 1);
	}

	printf("diagnose link kinds: produced and shared kept apart%s\n",
	       fails ? "" : " - ok");
	return fails != 0;
}
