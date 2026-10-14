/*
 * detectors/linkage/kofdiag.h - the matcher of a diagnose: does the code an
 * object holds do what a diagnose says.
 *
 * LINKAGE is the quality of the links between nodes. What it reads is built by
 * the genotyping of the object (libgenome/phenotype/diag_scan.h, included
 * here so a caller of the matcher sees the whole of it); what is here walks a
 * diagnose tree over those nodes and names the result.
 *
 * SEPARATE FROM THE BYTE MATCHERS, which are the other half of detection: they
 * ask what the BYTES are - a declared pattern, a block's similarity - and this
 * asks what the CODE DOES. They fail in different places, which is the only
 * reason to carry both: a recompile defeats the first and leaves the second; a
 * packer defeats the second and leaves the first once the payload is out.
 */

#ifndef KOFENG_KOFDIAG_H
#define KOFENG_KOFDIAG_H

#include <phenotype/diag_scan.h>
#include "../../analyzers/parsers/binaries/funcs.h"
#include <stdint.h>

#include "../../kofcore/koftypes.h"
#include "../../kofcore/kofmod/kofsig.h"   /* struct kof_obj_ctx */
#include "../../kofcore/kofcore.h"            /* kof_buf */
#include "../../kofcore/kofmod/kofdiagtree.h"

/*
 * DOES THIS DIAGNOSE CARRY THIS NAME - read at a call site its tree BOUND,
 * across every place the tree matched, and at no other.
 *
 * ONE NAME, because a list is the module's to compose: any is `||` and all is
 * `&&` over this, as kof_find_str_any and _all are over kof_find_str, and a
 * list passed across the module boundary is an array of pointers that a
 * position-independent module cannot keep out of writable data (measured: five
 * names put 40 bytes in .data and the builder refused the module).
 *
 * A name is a place a name was SEEN: a module that places a probe on two
 * symbols has two matches of the same tree with a name each, and both names
 * are carried. A diagnose that did not match at all carries nothing.
 *
 * kgenome_diag_str_at and _count are the ones that walk the list by capability,
 * for a caller that wants the list itself; THIS is the one a verdict reaches.
 */
int         kof_diag_scan_name(const struct kgenome_diag_scan *,
			       const struct kof_diag *, const char *name);
/*
 * DOES THIS OBJECT CARRY THIS DIAGNOSE. 1 or 0, and on 1 the node each of
 * the diagnose's nodes bound to is written to `bind_out`, in the order the
 * diagnose declares them. That is what a signature joins two diagnoses on -
 * see the note on kof_diag_share, which asks for a node of a given
 * capability that both of them bound.
 *
 * `bind_out` must have room for the diagnose's node count; NULL asks for the
 * bit alone, which is what kof_diag() costs.
 */
/*
 * DOES A NODE OF `cap` BOUND BY `b` REACH ANY NODE BOUND BY `a`, following
 * value-flow links - the transitive join a verdict asks. See the note in
 * kofdiag.c. The bind arrays are what kof_diag_match returned.
 */
int kof_diag_flow_join(struct kgenome_diag_scan *, uint16_t cap,
		       const uint16_t *a_bind, uint8_t na,
		       const uint16_t *b_bind, uint8_t nb);

int kof_diag_match(const struct kgenome_diag_scan *, const struct kof_diag *,
		   uint16_t *bind_out, uint8_t *n_bind);

/*
 * THE MATCHER WITH THREE ANSWERS. A 0 from kof_diag_match is an answer only when
 * the scan it reads is whole; when a limit was reached on it (the node store
 * filled, a run was stopped while it was still going) the calls past that point
 * are not in the graph and "no" would be a guess presented as a fact.
 *
 *   KOF_DIAG_MATCH_YES      1   it matched (a match is evidence however full the scan)
 *   KOF_DIAG_MATCH_NO       0   it did not, and the scan was whole
 *   KOF_DIAG_MATCH_UNKNOWN -1   it did not match, and a limit was reached: cannot say
 *
 * kof_diag_match stays the plain boolean for a caller that only asks "found".
 */
#define KOF_DIAG_MATCH_NO       0
#define KOF_DIAG_MATCH_YES      1
#define KOF_DIAG_MATCH_UNKNOWN (-1)
int kof_diag_match_known(const struct kgenome_diag_scan *, const struct kof_diag *,
			 uint16_t *bind_out, uint8_t *n_bind);

/*
 * SERIALISE THE GRAPH INTO THE RECORD BLOCK A RULE READS - see
 * kofmod/kofdiagtree.h. Returns the bytes written, or 0.
 *
 * A COPY, and deliberately: the engine's node array is its own working state
 * and grows while the analysis runs, while a rule reads a block that does not
 * move under it. The cost is bounded by the DATABASE rather than the object -
 * the graph has already been pruned to the capabilities some diagnose named.
 *
 * A RECORD CARRIES TWO LINKS (KOF_GR_IN_FIT), a node of the scan up to four. A
 * node with more has its first two written and the scan is noted
 * KGENOME_TRUNCATED: the scan is therefore not const, and the cut is read where
 * every other cut of the graph is (kof_scan_incomplete).
 */
uint32_t kof_diag_graph_build(struct kgenome_diag_scan *s, uint8_t *out,
			      uint32_t cap);

/*
 * READ ONE DIAGNOSE RECORD, as carried in a diag-<kind>.kdig pack. 1 on success, 0 when the bytes do not add up - and a
 * file that does not add up is refused WHOLE. The caller owns `node` and
 * `name`; nothing here allocates, so a load cannot fail halfway and leave
 * something to free.
 */
/*
 * THE STORAGE A RECORD IS LOADED INTO - one concept, the caller's: the node
 * array, the name and the string store beside the signs, each with its capacity.
 * `needs` may be NULL (with needs_cap 0) for a caller that wants no sign words.
 */
struct kof_diag_store {
	struct kof_diag_node *node;
	char                 *name;
	char                 *needs;
	uint32_t              name_cap;
	uint32_t              needs_cap;
	uint8_t               max_node;
};

int kof_diag_load(kof_buf rec, struct kof_diag *out, const struct kof_diag_store *st);

#endif /* KOFENG_KOFDIAG_H */
