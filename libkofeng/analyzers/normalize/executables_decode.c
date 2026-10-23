/*
 * executables_decode.c - the layered driver of the decode: the passes of executables.c, and the
 * escape pass of executables_esc.c, run round after round over what each round wrote. See
 * kof_exe_decode in executables.h.
 */

#include <stdlib.h>
#include <string.h>

#include "executables.h"
#include "executables_private.h"

/* The most bytes all the rounds together may walk, as a multiple of the object.
 * See kof_exe_decode_ex for what it bounds and why this number. */
#define DEC_WORK_FACTOR 8u

int kof_exe_decode(uint8_t *p, uint64_t n)
{
	return kof_exe_decode_ex(p, n, NULL);
}

int kof_exe_decode_ex(uint8_t *p, uint64_t n, struct kof_exe_decode_res *res)
{
	struct dec_out cur, nxt, tmp;
	uint64_t work, spent;
	uint32_t k;
	int changed = 0;
	struct kof_exe_decode_res none;

	if (!res)
		res = &none;
	memset(res, 0, sizeof *res);
	if (!p || !n)
		return 0;
	/*
	 * ROUNDS END WHEN A ROUND PEELS NOTHING, and are bounded by work, not by a
	 * count. This was `r < 4`: a payload under a fifth layer stayed encoded and
	 * nothing said so. Each round walks only what the one before produced, and a
	 * decoded run is shorter than its source, so honest layering walks less every
	 * round and ends of itself. What is left to bound is the hostile case - the
	 * percent decode leaves a run nearly as long as it was, so a crafted nest of
	 * escapes could peel one layer per round over a megabyte for ever - and that
	 * is a budget on the BYTES WALKED over all rounds: eight times the object.
	 * Measured honest layering (a payload under six layers) walks under two.
	 * When the budget is gone the remaining stretches are counted in `dropped`
	 * and `limit` says so.
	 */
	work = DEC_WORK_FACTOR * n;
	spent = n;                      /* round zero is the whole object */
	dec_out_init(&cur, n, 1);
	dec_out_init(&nxt, n, 1);
	kof_exe_dec_note(&cur, 0, n);

	while (cur.n) {
		nxt.n = 0;
		res->rounds++;
		for (k = 0; k < cur.n; k++) {
			uint64_t a = cur.v[k].off;
			uint64_t b = a + cur.v[k].len;

			if (!cur.v[k].len)
				continue;
			if (res->rounds > 1u) {
				if (cur.v[k].len > work - spent) {
					res->limit |= KOF_EXE_DEC_WORK;
					res->dropped += cur.n - k;
					break;
				}
				spent += cur.v[k].len;
			}
			/*
			 * Base64 first, because its anchor is a decoder named
			 * in the text and hex has no anchor at all - so where
			 * both could read the same run, the one that was told
			 * what it is reads it.
			 */
			changed |= kof_exe_pass_b64(p, n, a, b, &nxt);
			changed |= kof_exe_pass_hex(p, n, a, b, &nxt);
			changed |= kof_exe_pass_esc(p, n, a, b, &nxt);
			/* Last of the three: its runs are the widest - a URL
			 * is mostly ordinary characters - so a base64 or hex
			 * payload sitting inside one is read as itself first
			 * and this only sees what is left. */
			changed |= kof_exe_pass_pct(p, n, a, b, &nxt);
		}
		if (res->limit & KOF_EXE_DEC_WORK)
			break;
		tmp = cur;
		cur = nxt;
		nxt = tmp;
	}
	res->limit |= cur.limit | nxt.limit;
	res->scanned = spent;
	free(cur.v);
	free(nxt.v);
	return changed;
}
