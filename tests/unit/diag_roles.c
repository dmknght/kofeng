/*
 * diag_roles - the invariant kof_diag_note_in rests on, checked instead of
 * assumed.
 *
 * WHAT A LINK IS IDENTIFIED BY. A link says "this input of the child came
 * from that parent", and the model identifies it by (parent, role, kind) -
 * see enum kof_diag_kind for the third field, which says WHICH relation it
 * is. The role is the part a capability's table controls, and the part that
 * can be got wrong by hand.
 * kof_diag_note_in refuses one it already holds, because a run that goes
 * round a loop arrives at the same call with the same value from the same
 * producer, and that is one relation seen twice rather than two relations.
 *
 * WHICH IS ONLY CORRECT WHILE NO CALL HAS TWO INPUTS WEARING ONE ROLE. If it
 * does, two genuinely different relations collapse to one and the second is
 * dropped without a word - which is the worst shape a fault can have here,
 * because the output still looks like an answer.
 *
 * MEASURED, and that is why this file exists: a hooked getdents is
 *
 *     copy_from_user(kbuf, ubuf, n);   edit kbuf;   copy_to_user(ubuf, kbuf, n);
 *
 * and the pair shares two objects. Both arguments of copy_to_user were given
 * the role `buffer`, so the kernel source and the userspace destination became
 * the same link and one of them vanished. The repair was a second word
 * (KOF_DIAG_ROLE_SOURCE) - and the lesson is that a table a human maintains
 * will drift back unless something fails when it does.
 *
 * THE KIND DOES NOT RESCUE THIS. Two arguments of one call wearing one role
 * are the same kind as each other - both are what the caller was handed - so
 * they still collapse. See tests/unit/diag_kind.c for the other half.
 *
 * SO THIS WALKS THE WHOLE CAPABILITY SPACE. Not the capabilities that have
 * roles today: every value a capability can take, so a word added next year
 * is covered by a test written this year.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../../libkofeng/kofcore/kofmod/kofsig.h"
#include "../../libkofeng/kofcore/kofmod/kofcap.h"
#include "../../libkofeng/kofcore/kofmod/kofpathogen.h"
#include "../../libkofeng/analyzers/nucleo/nucleo.h"
#include "../../libkofeng/detectors/pathogen/diag_int.h"

static int fails;

/* How many arguments any call in this model has. The ABI's six; a seventh
 * would be on the stack and nothing here reads one. */
#define N_ARG 6u

int main(void)
{
	uint32_t c;
	unsigned checked = 0, with_roles = 0;

	for (c = 1u; c < 0x10000u; c++) {
		uint8_t seen[KOF_DIAG_ROLE_COUNT];
		unsigned i, any = 0;

		if (!KOF_NUCLEO_VALID(c))
			continue;
		checked++;
		memset(seen, 0, sizeof seen);
		for (i = 0; i < N_ARG; i++) {
			uint8_t r = kof_diag_role_of_arg((uint16_t)c, i);

			if (r == KOF_DIAG_ROLE_NONE)
				continue;
			any = 1;
			if (r >= KOF_DIAG_ROLE_COUNT) {
				printf("  FAIL %s: argument %u has role %u, "
				       "which is not a role\n",
				       kof_flow_cap_name((uint16_t)c)
					       ? kof_flow_cap_name((uint16_t)c)
					       : "?",
				       i, r);
				fails++;
				continue;
			}
			if (seen[r]) {
				const char *nm =
					kof_flow_cap_name((uint16_t)c);

				printf("  FAIL %s: arguments %u and %u both "
				       "carry role %u - two different inputs "
				       "under one word, and kof_diag_note_in "
				       "will drop one of them\n",
				       nm ? nm : "?", seen[r] - 1u, i, r);
				fails++;
			}
			seen[r] = (uint8_t)(i + 1u);
		}
		if (any)
			with_roles++;
	}

	/*
	 * AND THE WALK ITSELF HAS TO HAVE HAPPENED. A test that silently
	 * examined nothing passes for the wrong reason - it has been written
	 * twice in this tree already.
	 */
	if (checked < 64u) {
		printf("  FAIL the capability space answered %u valid values; "
		       "the walk found nothing to check\n", checked);
		fails++;
	}
	if (with_roles < 8u) {
		printf("  FAIL only %u capabilities assign any role at all; "
		       "the table is not being read\n", with_roles);
		fails++;
	}

	printf("diagnose roles: %u capabilities, %u with roles, none wearing "
	       "one word twice%s\n", checked, with_roles, fails ? "" : " - ok");
	return fails != 0;
}
