/*
 * kofhit.h - what a module can say about an object without naming it: mark where
 * damage is, or note what it worked out.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 *
 * THERE IS NO "REPORT A FINDING" HERE, and that is the point of the file's size. A
 * module does not say what an object is: the object is named by the diseases it
 * has (kof_verdict_make), and a disease is declared by a diagnose. What a module
 * can still do is say WHERE something is (kof_mark_infected) and what it found
 * out on the way (kof_debug); neither names, ranks or ends anything.
 */

#ifndef KOFENG_KOFHIT_H
#define KOFENG_KOFHIT_H

#include <stdint.h>
#include "kofctx.h"

/*
 * MARK A RANGE OF THIS OBJECT AS INFECTED - see `struct kof_infected`.
 *
 *     kof_mark_infected(body_off, body_len, KOF_INF_BODY);
 *     kof_mark_infected(ctx->entry_off, saved, KOF_INF_DAMAGE);
 *
 * A fact about a PLACE and nothing else: it makes no verdict and offers no
 * repair, and a caller may use it without either.
 */
#define kof_mark_infected(off, len, kind)                                  \
	((ctx)->content->infected                                          \
	 ? (ctx)->content->infected((ctx), (uint64_t)(off),                \
				    (uint64_t)(len), (uint32_t)(kind))     \
	 : (void)0)

/*
 * Say what was worked out, without deciding anything.
 *
 * This is for the cases where the useful information is not an answer - which
 * packer version was recognised, how far a block chain got, which coding a
 * stream used - and where stopping would be wrong because the module has work left
 * to do. It reports and carries on.
 *
 * The name is a literal, extracted at build time, so it costs the blob nothing.
 * `value` is one number the module computed; pass zero when there is nothing to
 * say beyond the name.
 *
 *     kof_debug("UPX.PE.NRV2E", version);
 *
 * Invisible unless the host asked. Nothing in the scan path reads these and no
 * verdict depends on one, so leaving them in a shipped module costs a NULL test
 * per call - which is why they are meant to be left in.
 */
#define kof_debug(name, value)                                              \
	((void)((ctx)->debug ?                                              \
		((ctx)->debug((ctx), (uint32_t)__LINE__, (uint64_t)(value)), 0) : 0))

#endif /* KOFENG_KOFHIT_H */
