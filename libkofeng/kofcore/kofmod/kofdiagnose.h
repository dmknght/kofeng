/*
 * kofdiagnose.h - asking the host whether a diagnose matched: kof_diag, the id
 * of a name, and the share of a node.
 *
 * Part of the module ABI; a module includes <kofmod/kofsig.h>, never this file.
 */

#ifndef KOFENG_KOFDIAGNOSE_H
#define KOFENG_KOFDIAGNOSE_H

#include <stdint.h>
#include "kofctx.h"

/*
 * DOES THIS OBJECT CARRY A DIAGNOSE.
 *
 *     if (kof_diag(DIAG_RWX_EXEC))
 *             kof_debug("rwx-exec", 0);
 *
 * A diagnose describes WHAT THE CODE DOES and names no family; the disease it
 * declares is where the verdict and the name come from. That split is the
 * whole point of the two: the shape of a self-unpacking loader has not
 * changed in twenty years, and a family name changes weekly.
 *
 * Several diagnoses named together are a narrower question, and no new
 * mechanism is needed - `&&` is the same `&&` every other condition uses.
 *
 * THE NAME IS WRITTEN AS AN IDENTIFIER, not as a string: the macro
 * stringifies it and hashes it the same way the loader hashed the
 * diagnose's own KOF_DIAG_NAME. Spelling it the way a C constant is spelt
 * is what makes a rule read as naming a THING rather than quoting a label,
 * and it is the same spelling the diagnose file uses.
 *
 * Zero always answers no - a name no diagnose carries, a database with
 * none loaded, a format the analysis does not run on.
 */
#define kof_diag(name) \
	((ctx)->content->diag32 ? (ctx)->content->diag32((ctx), \
							 kof_diag_id32_(#name)) : 0)

/*
 * THE ID OF A DIAGNOSE, FROM ITS NAME.
 *
 *     if (kof_diag(KOF_DIAG_ID("trojan_meterp_00")))
 *             kof_debug("trojan-meterp", 0);
 *
 * A HASH AND NOT A REGISTRY, which is the convention this tree already
 * settled on for heuristic variants: "stable across rebuilds without a
 * registry". The id used to be the diagnose's position in the load order,
 * which is readdir order - it changed when a file was added, and no rule
 * could name one at all.
 *
 * THIRTY-TWO BITS: FNV-1a over the name, never zero (zero means "no diagnose").
 * It was a 16-bit fold of the same hash (kof_diag_fold16_, which the three
 * 16-bit slots of the vtable still take, for a module built before), and two names
 * that folded alike could not both be loaded. The loader still refuses a database
 * where two diagnoses collide in the full id rather than letting one answer for
 * the other.
 */
static inline uint32_t kof_diag_id32_(const char *s)
{
	uint32_t h = 2166136261u;

	while (*s) {
		h ^= (uint8_t)*s++;
		h *= 16777619u;
	}
	return h ? h : 1u;
}

/* The 16-bit id the old slots take: the fold the id used to be. Computed from the
 * full id, so the two always agree. */
static inline uint16_t kof_diag_fold16_(uint32_t id32)
{
	uint32_t h = (id32 ^ (id32 >> 16)) & 0xffffu;

	return (uint16_t)(h ? h : 1u);   /* zero means "no diagnose" */
}

static inline uint16_t kof_diag_id_(const char *s)
{
	return kof_diag_fold16_(kof_diag_id32_(s));
}

#define KOF_DIAG_ID(name) kof_diag_id32_(name)

/*
 * DO TWO DIAGNOSES MEET AT A NODE OF THIS CAPABILITY.
 *
 *     if (kof_diag_share(KOF_NUCLEO_MEM_READ, DIAG_MEM_EXECSYSCALL,
 *                        DIAG_NET_RECVSYSCALL))
 *             kof_debug("stager", 0);
 *
 * Both matched AND one node of capability `cap` was bound by both.
 *
 * THE CAPABILITY IS NAMED BECAUSE THE SHAPE IS. A W+X region filled by a
 * read, and a socket whose descriptor that same read uses, is a stager -
 * and what makes it one is that the READ is the same read. "They have some
 * node in common" would also be true of two behaviours sharing an
 * allocation or a resolve, which a packed binary is full of.
 *
 * `kof_diag(a) && kof_diag(b)` is weaker still and a different question: a
 * file can carry a packer and a downloader without the packer's region
 * being what the downloader filled.
 */
/*
 * DOES THIS DIAGNOSE CARRY THESE NAMES.
 *
 *     if (kof_diag_str_any(DIAG_LKM_KPROBE_RESOLVE, "sys_call_table"))
 *             kof_debug("kprobe-resolve", 0);
 *
 *     kof_diag_str_all(DIAG_X, "a", "b")
 *
 * The first argument is the diagnose, spelled as the enum the diagnose itself
 * declares with KOF_DIAG_NAME - the same word kof_diag() takes. The rest are
 * names.
 *
 * The same pair as kof_find_str_any and kof_find_str_all, with a diagnose
 * where the range was: `any` is true when ONE of the names is present, `all`
 * when EVERY one is. Each is one statement a rule editor can show as a block
 * - "this diagnose, with these names" - and they compose with && and ||.
 *
 * THE NAMES BELONG TO THE DIAGNOSE, not to a capability. They are the ones the
 * analysis read out of the emulator's memory at the calls the diagnose's nodes
 * stand for, and kept in the engine; a module asks, it does not go and look.
 * See kof_flow_name_arg for which capabilities are handed a name and where,
 * and kof_diag_str_add for why a name is a copy and not an offset into the
 * file.
 *
 * IT IS FALSE UNLESS THE DIAGNOSE MATCHED. A name only means anything beside
 * the behaviour it was handed to, and a call that asks for the names of a
 * diagnose that did not fire has asked for nothing - so there is no need to
 * write kof_diag() beside it and no way to get the order wrong.
 *
 * FALSE IS "NOT FOUND", NEVER "NOT THERE", and the difference is not small.
 * The names come from calls the span runner REACHED. One it could not reach -
 * hcrootkit's register_kprobe sits behind a 50-iteration initialisation loop
 * the run will not execute - leaves no name at all, and a verdict that reads
 * that as "the module never named it" has drawn a conclusion from silence.
 *
 * THE NAMES ARE LITERALS, which live in the blob like any other: the engine
 * hashes each and then compares the bytes, so a hash collision cannot make a
 * name appear. At most KOF_DIAG_STR_MAX are taken in one call.
 */
#define KOF_DIAG_STR_MAX 8u
#define kof_diag_str_one(diag, name) ((ctx)->content->diag_str32 ? \
	(ctx)->content->diag_str32((ctx), kof_diag_id32_(#diag), (name)) : 0)
#define KOF_DFS_1(op, d, a)       kof_diag_str_one(d, a)
#define KOF_DFS_2(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_1(op, d, __VA_ARGS__))
#define KOF_DFS_3(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_2(op, d, __VA_ARGS__))
#define KOF_DFS_4(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_3(op, d, __VA_ARGS__))
#define KOF_DFS_5(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_4(op, d, __VA_ARGS__))
#define KOF_DFS_6(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_5(op, d, __VA_ARGS__))
#define KOF_DFS_7(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_6(op, d, __VA_ARGS__))
#define KOF_DFS_8(op, d, a, ...) (kof_diag_str_one(d, a) op KOF_DFS_7(op, d, __VA_ARGS__))
#define KOF_DFS_FOLD(op, d, ...) \
	KOF_PASTE(KOF_DFS_, KOF_NARG(__VA_ARGS__))(op, d, __VA_ARGS__)
#define kof_diag_str_any(diag, ...) KOF_DFS_FOLD(||, diag, __VA_ARGS__)
#define kof_diag_str_all(diag, ...) KOF_DFS_FOLD(&&, diag, __VA_ARGS__)

#define kof_diag_share(cap, a, b) ((ctx)->content->diag_share32 ? \
				   (ctx)->content->diag_share32((ctx), \
								(uint16_t)(cap), \
								kof_diag_id32_(#a), \
								kof_diag_id32_(#b)) \
				 : 0)

/*
 * THE BEHAVIOUR MACROS ARE GONE, and so is the chain they were shaped by.
 *
 * kof_pth_has, kof_pth_feeds and kof_pth_match were the whole of what a rule
 * could ask about behaviour, and all three are shaped by the chain: a
 * sequence of steps with a distance back to the one that fed each. Three
 * things that shape cannot hold, and each of them is the ordinary case:
 *
 *   - one producer with several consumers is a TREE, not a list;
 *   - a step joined to another by CONTROL rather than by a value has no
 *     place in it at all, which is why `vfork` then `execl("/bin/sh")` was
 *     dropped off a page that had already found both;
 *   - a distance in a sequence is broken by inserting one step between two,
 *     which makes it the one part of a rule an author can evade on purpose.
 *
 * They will come back against a store of NODES AND TYPED EDGES rather than
 * chains. What was kept is the VOCABULARY they spent - kofmod/kofcap.h -
 * because which capability a name or a syscall number means is the part that
 * was right. Removed rather than left in place because a module written
 * against them now would have to be rewritten, and bases/ has none yet -
 * which is the only moment this costs nothing.
 */

#endif /* KOFENG_KOFDIAGNOSE_H */
