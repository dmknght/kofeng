/*
 * kofhit.h - what a module does when it finds something: report it, mark it,
 * say it can be cured, or note what it worked out.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFHIT_H
#define KOFENG_KOFHIT_H

#include <stdint.h>
#include "kofctx.h"

/*
 * Report a finding and stop. The level is the macro, not a parameter - so a reader
 * sees what was decided without looking up a second argument.
 *
 *     KOF_SCAN_INFECT("Variant-42bb");     custom variant, this module's own text
 *     KOF_SCAN_INFECT(KOF_MALVAR_GENERIC); the family's one generic bucket
 *     KOF_SCAN_INFECT(KOF_MALVAR_AUTO);    variant derived from the guarding pattern
 *     KOF_SCAN_SUSPECT(...)                same three forms, KOF_LVL_SUSPECT instead
 *
 * The name id is the source line, which is why the argument can be dropped from the
 * expansion below: the build scans this source, resolves whichever of the three
 * forms was written, composes it with the KOF_TARGET_NAME this file declared, and
 * writes "<line> <name>" into a table the host loads beside the blob. Same mechanism
 * every declaration here uses, and the same failure mode - a table out of step with
 * the blob shows up as a missing name, never as a wrong one.
 *
 * KOF_MALVAR_GENERIC and KOF_MALVAR_AUTO need no #define to compile - the argument is
 * never evaluated, only read as text by the build - but are given self-referential
 * ones below so an editor does not flag them as undeclared.
 *
 * KOF_MALVAR_AUTO must directly guard - be the sole condition of the enclosing
 * if (kof_find_str_any/all/multi(...)) - because the variant it produces is a hash of
 * that call's region and patterns, not of anything KOF_SCAN_INFECT/SUSPECT itself is
 * given. That is what makes it stable across rebuilds without a registry: the same
 * patterns in the same region hash the same way every time, and a module compiled
 * next to a hundred others does not need to know what they are named.
 *
 * Takes no context, for the reason the search macros do not: it names `ctx`, which
 * KOF_DEFINE_SCAN put in scope. Leaving it explicit here while the searches beside it
 * are not would be the worst of both - a parameter that is sometimes required and
 * never meaningful.
 *
 * The report and the return are one statement so neither half can be forgotten.
 */
#define KOF_MALVAR_AUTO    KOF_MALVAR_AUTO
#define KOF_MALVAR_GENERIC KOF_MALVAR_GENERIC

/*
 * SAY THAT THIS ONE CAN BE PUT BACK, and where the damage begins.
 *
 *     if (kof_find_str_at(ctx->entry_off, stub)) {
 *             KOF_SCAN_CURABLE(ctx->entry_off);
 *             KOF_SCAN_INFECT(KOF_MALVAR_AUTO);
 *     }
 *
 * BEFORE THE VERDICT, because a verdict returns. It is not a verdict itself
 * and reports nothing: the object is still infected and is still named as
 * such. What it adds is that the module knows how to undo it, which the host
 * may act on and may equally ignore.
 *
 * ONLY WHERE THE MATCH WAS ANCHORED. A pattern found SOMEWHERE in a region
 * says the payload is present; a pattern found AT an offset the module
 * worked out says where it is. Only the second can lead to a repair, and
 * calling this after the first would be offering to cut at an address nobody
 * established.
 */
#define KOF_SCAN_CURABLE(at)                                               \
	((ctx)->content->cure_offer                                        \
	 ? (ctx)->content->cure_offer((ctx), (uint64_t)(at)) : (void)0)

/*
 * MARK A RANGE OF THIS OBJECT AS INFECTED - see `struct kof_infected`.
 *
 *     kof_mark_infected(body_off, body_len, KOF_INF_BODY);
 *     kof_mark_infected(ctx->entry_off, saved, KOF_INF_DAMAGE);
 *
 * Says nothing on its own: the verdict is still KOF_SCAN_INFECT's and the
 * repair is still kcure_patch's. This is the third statement - WHERE - and a
 * caller may use it without acting on either of the others.
 */
#define kof_mark_infected(off, len, kind)                                  \
	((ctx)->content->infected                                          \
	 ? (ctx)->content->infected((ctx), (uint64_t)(off),                \
				    (uint64_t)(len), (uint32_t)(kind))     \
	 : (void)0)

/*
 * THE TWO THINGS A CURE CAN ASK FOR - see kof_content.cure_patch.
 *
 *     void kof_cure(const struct kof_obj_ctx *ctx)
 *     {
 *             uint8_t b[4];
 *             uint64_t orig = kof_u32(ctx->entry_off + 1u);
 *
 *             b[0] = (uint8_t)orig;  b[1] = (uint8_t)(orig >> 8);
 *             b[2] = (uint8_t)(orig >> 16); b[3] = (uint8_t)(orig >> 24);
 *             kcure_patch(24, b, 4);        (* e_entry *)
 *             kcure_truncate(ctx->entry_off);
 *     }
 *
 * Both return non-zero when the host accepted the request. A cure that is
 * refused has still described itself, which is what a caller that wants to
 * show a repair before applying it reads.
 */
#define kcure_patch(off, bytes, n)                                      \
	((ctx)->content->cure_patch                                        \
	 ? (ctx)->content->cure_patch((ctx), (uint64_t)(off),              \
				      (const uint8_t *)(bytes),            \
				      (uint32_t)(n)) : 0)

#define kcure_truncate(len)                                             \
	((ctx)->content->cure_truncate                                     \
	 ? (ctx)->content->cure_truncate((ctx), (uint64_t)(len)) : 0)

/*
 * AND THE REST OF THE CURE SURFACE, which is the arithmetic rather than the
 * two requests. Included HERE, after struct kof_content, because every macro
 * in it reaches through that - see the note at the top of kofcure.h, which
 * this file has named since kof_scan was first written.
 */
#include "kofcure.h"

#define KOF_SCAN_INFECT(variant)                                            \
	do {                                                                \
		(ctx)->report((ctx), (uint32_t)KOF_LVL_INFECT, (uint32_t)__LINE__); \
		return;                                                     \
	} while (0)

#define KOF_SCAN_SUSPECT(variant)                                           \
	do {                                                                \
		(ctx)->report((ctx), (uint32_t)KOF_LVL_SUSPECT, (uint32_t)__LINE__); \
		return;                                                     \
	} while (0)

/*
 * Say what was worked out, without deciding anything.
 *
 * KOF_SCAN_MATCH reports and returns; this reports and carries on. It is for the cases
 * where the useful information is not the verdict - which packer version was
 * recognised, how far a block chain got, which coding a stream used - and where
 * stopping would be wrong because the module has work left to do.
 *
 * The name is a literal, extracted at build time exactly as a detection name is,
 * so it costs the blob nothing. `value` is one number the module computed; pass
 * zero when there is nothing to say beyond the name.
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
