/*
 * lineageview.h - one function's slice of an object's whole value-flow graph
 * (kof_result.lineage) as a generic graph a viewer draws (struct kgenome_gv,
 * celllysis/gview.h): EVERY input of every node inside the function, of every
 * kind the lineage stage gives (PROVEN, MAY, UNKNOWN, BROKEN: the edge's `sure`),
 * and one LINK ROW per input (gv.note[], the edge it is drawn as in note.link).
 *
 * A LINEAGE FILLER OF GVIEW.H'S OWN KIND - cfg_gv.c's header comment says "a
 * lineage filler is this file with other nodes and other kinds", and this is
 * that filler. It sits in the ENGINE rather than in libgenome: what it fills
 * FROM, struct kof_diag_lineage_rec, is the engine's own snapshot of
 * libgenome's kgenome_diag_scan (st_report_lineage, scan_pipeline.c), made to
 * outlive the scan for a dialog that reads it long after the scanner that
 * made it is gone - libgenome has no such type to fill from.
 *
 * A LINK WITH NO EDGE IS STILL A ROW. An input whose producer is outside the
 * caller's extent, the stack, or a record that does not exist has no box to
 * start from: it is not drawn, and its row says where it came from (the cap must
 * not lose evidence, CLAUDE.md rule 4). The rows are the one list of the links;
 * there is no second (aside) list beside them.
 */
#ifndef KOF_LINEAGEVIEW_H
#define KOF_LINEAGEVIEW_H

#include <celllysis/gview.h>

#include "../kofcore/kofresult.h"

struct kof_lineageview_req {
	const struct kof_diag_lineage_rec *lin;
	uint32_t                           n_lin;
	uint64_t                           off, len;   /* the function's own extent */
	const char                        *title[2];   /* head lines above the drawing, as kgenome_cfg_gv_req's own; either may be NULL */
	/* The object's own bytes, to turn a node's symref (a file offset into them) into the name it
	 * read - the one place this filler needs the object at all. NULL/0: a symref is said as a
	 * bare offset instead of a name (degraded, not silent). */
	const uint8_t                     *base;
	uint64_t                           size;
	/* EVERY INPUT of the nodes (kof_result.lineage_in: a record's are [in_first, in_first + n_all)). NULL: each record's
	 * four-input view (in[]) is all there is - a system call's NUMBER and a fifth input are never in it, and the head
	 * says the links were read from the view. Appended: an initialiser that does not name it keeps the old reading. */
	const struct kof_diag_lineage_in  *lin_in;
	uint32_t                           n_lin_in;
};

enum kgenome_status kof_lineageview_build(const struct kof_lineageview_req *rq, struct kgenome_gv *out);

#endif /* KOF_LINEAGEVIEW_H */
