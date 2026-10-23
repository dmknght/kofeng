/*
 * diag_linked_how - a MAY link satisfies a diagnose exactly as a PROVEN one does, on purpose.
 *
 * `linked()` in kofdiag.c never reads the link's `how`. The audit listed it as a defect (R4: "MAY
 * satisfies a diagnose like PROVEN"). It is a DECISION, and this test is what makes it one and not an
 * accident: the diagnose asks "is there a relation between these two nodes", the engine's routes already
 * keep a link only when the program can produce it (MAY says "on some path, or through a callee not read",
 * never "guessed"), and a diagnose that had to say which would be two diagnoses. How sure a link is, is
 * reported (kgenome_diag_in.how, the dump, the viewer); it does not select. If the decision changes, this
 * test is the one to change, and the corpus identity counts move with it.
 *
 * Also pinned here, because the stale comment about it was corrected with this test: a node holds four
 * links, and the FIFTH distinct one is not silent - note_in_how answers 1 and the scan says
 * KGENOME_TRUNCATED (diag_lineage.h, stats.dropped).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofdiagtree.h"
#include "../../libkofeng/detectors/linkage/kofdiag.h"
#include <phenotype/diag_private.h>

static int fails;

#define CK(x) do { if (!(x)) { \
	printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #x); fails++; } \
	} while (0)

static int match_with(uint8_t how)
{
	struct kgenome_diag_hit hits[2];
	struct kgenome_diag_scan s;
	struct kgenome_diag_hit *h;
	static const struct kof_diag_node nd[] = {
		{ .cap = KGENOME_NUCLEO_NET_OPEN, .parent = KOF_DIAG_NO_PARENT, .role = KGENOME_DIAG_ROLE_NONE },
		{ .cap = KGENOME_NUCLEO_NET_WRITE, .parent = 0, .role = KGENOME_DIAG_ROLE_FD },
	};
	static const struct kof_diag dg = { .id = 1, .analysis = KOF_DIAG_ANALYSIS_SYMBOL, .n_node = 2,
					    .name = "open-then-write", .node = nd };

	memset(hits, 0, sizeof hits);
	memset(&s, 0, sizeof s);
	s.hit = hits;
	s.cap_hit = 2u;
	CK(kgenome_diag_hit_add(&s, 0x10, KGENOME_NUCLEO_NET_OPEN, 0) != NULL);
	CK(kgenome_diag_hit_add(&s, 0x20, KGENOME_NUCLEO_NET_WRITE, 0) != NULL);
	h = kgenome_diag_hit_of(&s, 1u);
	CK(h != NULL);
	if (h)
		CK(kgenome_diag_note_in_how(&s, h, 0u, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED, how) == 0);
	return kof_diag_match(&s, &dg, NULL, NULL);
}

int main(void)
{
	struct kgenome_diag_hit hits[8];
	struct kgenome_diag_scan s;
	struct kgenome_diag_hit *h;
	uint16_t i;

	CK(match_with(KGENOME_DIAG_LINK_PROVEN) == 1);
	CK(match_with(KGENOME_DIAG_LINK_MAY) == 1);

	memset(hits, 0, sizeof hits);
	memset(&s, 0, sizeof s);
	s.hit = hits;
	s.cap_hit = 8u;
	for (i = 0; i < 7u; i++)
		CK(kgenome_diag_hit_add(&s, 0x10u + i, KGENOME_NUCLEO_NET_OPEN, 0) != NULL);
	h = kgenome_diag_hit_of(&s, 6u);
	CK(h != NULL);
	if (h) {
		for (i = 0; i < 4u; i++)
			CK(kgenome_diag_note_in_how(&s, h, i, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED,
						KGENOME_DIAG_LINK_MAY) == 0);
		CK(kgenome_diag_scan_status(&s) == KGENOME_OK);
		/* a repeat is not a fifth */
		CK(kgenome_diag_note_in_how(&s, h, 0u, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED,
					KGENOME_DIAG_LINK_MAY) == 0);
		CK(kgenome_diag_scan_status(&s) == KGENOME_OK);
		/* the fifth distinct one is dropped and said */
		CK(kgenome_diag_note_in_how(&s, h, 4u, KGENOME_DIAG_ROLE_FD, KGENOME_DIAG_KIND_PRODUCED,
					KGENOME_DIAG_LINK_MAY) == 1);
		CK(kgenome_diag_scan_status(&s) == KGENOME_TRUNCATED);
		CK(h->n_in == 4u);
	}
	printf("diag_linked_how: %d failure(s)\n", fails);
	return fails != 0;
}
