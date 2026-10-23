/*
 * executables_probe.c - two questions about an object answered by READING it, so that the
 * normaliser takes its working buffer only when a view can result. See scan_norm.c.
 */
#include <stdlib.h>
#include <string.h>
#include <kofcore.h>

#include "executables.h"
#include "executables_private.h"

/*
 * WOULD kof_exe_decode_ex CHANGE ANYTHING - answered without a copy of the object.
 *
 * The first round of the decode is the whole object read by the four passes in
 * order, each writing in place; a pass that finds nothing leaves the bytes as they
 * were, so the next reads the original, and a round that peeled nothing ends the
 * decode. So "nothing would be decoded" is exactly "the first round reaches no
 * point where it writes", and that is a READ of the object: each pass runs as it
 * runs, and where it would write it answers yes instead (probe). A bound firing
 * counts as yes (the real run would report it). The cost is the first round's
 * reading, which the real decode pays too; what it saves is the copy of the
 * object the decode needs to run on.
 */
int kof_exe_decode_would_change(const uint8_t *p, uint64_t n)
{
	struct dec_out nxt;
	int changed;

	if (!p || !n)
		return 0;
	dec_out_init(&nxt, n, 1);
	nxt.probe = 1;
	/* The passes take a writable pointer and never write in probe mode. */
	changed = kof_exe_pass_b64((uint8_t *)(uintptr_t)p, n, 0, n, &nxt) ||
		  kof_exe_pass_hex((uint8_t *)(uintptr_t)p, n, 0, n, &nxt) ||
		  kof_exe_pass_esc((uint8_t *)(uintptr_t)p, n, 0, n, &nxt) ||
		  kof_exe_pass_pct((uint8_t *)(uintptr_t)p, n, 0, n, &nxt);
	changed = changed || nxt.limit != 0;
	free(nxt.v);
	return changed;
}

/*
 * IS THERE ANY RUN OF KOF_EXE_NORM_WIDE_MIN WIDE CHARACTERS, anywhere - a read, and
 * an over-estimate of what kof_exe_norm_masked would narrow (it narrows only inside
 * what is not kept, and this does not look at that). "No" is therefore exact: no run
 * anywhere is no run in the part that may be rewritten.
 */
int kof_exe_has_wide(const uint8_t *p, uint64_t n)
{
	uint64_t a;

	/*
	 * A WORD AT A TIME. A run of eight wide characters is sixteen contiguous bytes, so it
	 * contains an aligned 8-byte word whose bytes at every other position are zero and whose
	 * word is not all zero (a character's low byte is printable). That test is two masks on a
	 * load - about one instruction a byte - and a word that passes it is only a candidate: the
	 * run it sits in is walked out and counted exactly. Nothing a run can look like is missed,
	 * the byte order does not matter (both parities are tried), and it replaced a memchr per
	 * zero byte that cost 4 instructions a byte of object on a .NET PE.
	 */
	for (a = 0; a + 8u <= n; a += 8u) {
		uint64_t w, j;

		memcpy(&w, p + a, sizeof w);
		if (!w)
			continue;
		if ((w & 0xff00ff00ff00ff00ull) == 0)
			j = a;                  /* characters start at a, a+2, ... */
		else if ((w & 0x00ff00ff00ff00ffull) == 0 && a)
			j = a - 1u;             /* the low bytes are the odd ones */
		else
			continue;
		while (j >= 2u && wide_char(p[j - 2u], p[j - 1u]))
			j -= 2u;
		if (wide_run(p, n, j) >= KOF_EXE_NORM_WIDE_MIN)
			return 1;
	}
	return 0;
}
