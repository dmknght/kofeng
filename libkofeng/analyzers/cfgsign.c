/*
 * cfgsign.c - kof_cfgsign_function. See cfgsign.h for what it decides.
 *
 * ORDER OF WORK: the FRAME of the function (kgenome_frame_make through the object's cache: ONE decode through kgenome_diag_code_run, which given the object's walk
 * READS the walk's trace and decodes nothing, the precondition - can the algorithm hash this function - and the graph, built once for whoever asks: the signing
 * and the lineage read the same one) -> kgenome_cfg_sign -> the floor (kgenome_cfg_anchor). Nothing is decoded twice and no block is found twice.
 */
#include <stdlib.h>
#include <string.h>

#include <genotype/image/image_addr.h>
#include <phenotype/diag_scan.h>
#include <phenotype/frame.h>

#include "cfgsign.h"
#include "genome_obj.h"

#define DEFAULT_MAX_BYTES (64ull << 20)

const char *kof_cfgsign_state_name(enum kof_cfgsign_state s)
{
	switch (s) {
	case KOF_CFGSIGN_SIGNED: return "signed";
	case KOF_CFGSIGN_BELOW_FLOOR: return "below the floor";
	case KOF_CFGSIGN_UNDECODABLE: return "no instruction decodes";
	case KOF_CFGSIGN_UNSUPPORTED: return "no control-flow rules for this architecture";
	case KOF_CFGSIGN_OVER_BUDGET: return "over the allowance of one call";
	case KOF_CFGSIGN_NOMEM: return "no memory";
	}
	return "?";
}

void kof_cfgsign_release(struct kof_cfgsign *r, const struct kgenome_cfg_mem *mem)
{
	if (!r)
		return;
	kgenome_cfg_release(mem, r->in, r->in_bytes_);
	kgenome_cfg_release(mem, r->label, r->label_bytes_);
	kgenome_cfg_free(&r->g, mem);
	r->in = NULL;
	r->label = NULL;
	r->in_bytes_ = r->label_bytes_ = 0;
	memset(&r->g, 0, sizeof r->g);
}

static enum kof_cfgsign_state finish(struct kof_cfgsign *out, enum kof_cfgsign_state s)
{
	out->state = s;
	return s;
}

/*
 * WHY IT MATTERS NOW (owner, 2026-11-01): the first version used pattern matching only (bytes and strings), so an unpacker that restored the image a little wrong did not change a verdict much; today
 * ALL the data the detection uses is derived from the ARCHITECTURE of the file (the decoded instructions, the function table, the blocks, the call identities, the regions), so every defect of the
 * restored image (a filtered call target, a wrong region, a carve that took the file's own bytes) reaches the signature and the diagnose conditions. The reliability of the unpackers is therefore part of
 * the accuracy of the detection, not a side issue.
 * IMPROVE substrate-1 (owner, 2026-11-01; DONE for decode and frame 2026-11-03, phase A3a): one product per step, each computed ONCE and reused:
 *   1. DECODE -> reused: a function is decoded once (the walk trace, read through kgenome_diag_code_run, DEC-1); later steps read that result.
 *   2. ANALYSE THE FRAME (blocks with their byte start, edges, call sites, the facts of the instructions that need no other input) -> reused: kgenome_frame (libgenome/phenotype/frame.h),
 *      built once per function by the object's cache and read by this function and by the lineage (which used to build its own graph with `.be = 0` and a different block rule).
 *   3. BUILD THE HASH for the CFG signature or for lineage FROM THE FRAME, by the condition that holds (the frame's state is the precondition: kgenome_frame_make decides from the decoded
 *      metadata, before the graph is built, whether the algorithm can compute it), and use the result.
 *   Lineage needs MORE than the frame (owner, 2026-11-03): it takes the frame and adds its own analysis step on top (links, shared values, summaries), then uses that result; the frame is the shared base.
 * Open: a frame of a function in a normalised view (the view's table is the parent's found again by bytes: phase A3b); a frame for the architectures whose walk has no trace (CN-6).
 * IMPROVE cfg-input-1 (owner, 2026-11-01; NOTE ONLY, nothing built): the signature is only as good as the IMAGE it is computed on, and the unpackers that produce that image are not reliable enough
 * today; this lowers the accuracy of the CFG mutation detection. Measured so far (one run each): the UPX module leaves the ARM and PowerPC branch-with-link targets FILTERED (only the x86 filter ids are
 * undone: bases/unp/upx_elf_00.c, IMPROVE upx-code-1): the restored image differs from the reference unpacker's in 3722 bytes (Mirai.gen ARM) and 8646 bytes (Mirai.r PowerPC), all call displacements, so
 * call targets, function starts and the call identities (ckey) of the callee sketch are wrong on such an image (the effect on the shape signature itself was NOT measured: Inference); the sample Mirai.mr is
 * refused by the reference unpacker (altered header), so its restored image has no reference at all; the appended-ELF carve takes the file's own section area for a payload on a lying section table (Ark,
 * bases/decomp/appended_00.c). To do (not started): compare each unpacker module with its reference tool byte for byte on real samples and keep that comparison as the test of the module; and let the
 * engine SAY on the object that a block was left filtered or an image is unverified, so that the signing and the viewer can show it instead of presenting a signature as sound. */

static enum kof_cfgsign_state state_of(enum kgenome_frame_state s)
{
	switch (s) {
	case KGENOME_FRAME_UNSUPPORTED: return KOF_CFGSIGN_UNSUPPORTED;
	case KGENOME_FRAME_OVER_BUDGET: return KOF_CFGSIGN_OVER_BUDGET;
	case KGENOME_FRAME_NOMEM: return KOF_CFGSIGN_NOMEM;
	case KGENOME_FRAME_OK:                  /* (asked only of a frame that is not OK) */
	case KGENOME_FRAME_UNDECODABLE: break;
	}
	return KOF_CFGSIGN_UNDECODABLE;
}

enum kof_cfgsign_state kof_cfgsign_function(const struct kof_cfgsign_req *rq, struct kof_cfgsign *out)
{
	const struct kof_cfgsign_host *h = rq ? rq->host : NULL;
	const struct kgenome_cfg_mem *mem = h ? &h->mem : NULL;
	struct kgenome_obj gobj;
	struct kgenome_frame_src src;
	struct kgenome_frame own;
	const struct kgenome_frame *f;
	struct kgenome_cfg_sign_req sq;
	struct kgenome_budget bud;
	struct kgenome_cfg_anchor_req aq;
	uint64_t *label = NULL;
	size_t label_bytes = 0;
	enum kgenome_status st;

	memset(out, 0, sizeof *out);
	memset(&own, 0, sizeof own);
	if (!rq || !rq->ctx || !rq->data.p || !rq->len || rq->off >= rq->data.n || rq->len > rq->data.n - rq->off)
		return finish(out, KOF_CFGSIGN_UNDECODABLE);
	kof_genome_obj(rq->ctx, &gobj);
	memset(&src, 0, sizeof src);
	src.obj = &gobj;
	src.base = rq->data.p;
	src.size = rq->data.n;
	src.fs = rq->fs;
	src.wk = rq->wk;
	if (h)
		src.mem = h->mem;
	src.max_bytes = h && h->max_bytes ? h->max_bytes : DEFAULT_MAX_BYTES;
	/* THE FRAME: from the object's cache when the caller has one (the lineage reads the same), else made here; a viewer that keeps the graph makes its own, with the instructions. */
	if (rq->keep) {
		(void)kgenome_frame_make(&src, rq->off, rq->len, KGENOME_FRAME_KEEP_INSN, &own);
		f = &own;
	} else {
		f = kgenome_frame_of_extent(rq->frames, &src, rq->off, rq->len, &own);
	}
	if (!f) {
		out->status = KGENOME_NOMEM;
		return finish(out, KOF_CFGSIGN_NOMEM);
	}
	out->be = f->be;
	out->mapped = f->mapped;
	out->func_va = f->va;
	out->n_insn = f->n_insn;
	out->n_skip = f->n_skip;
	out->status = f->status;
	if (f->state != KGENOME_FRAME_OK) {
		kgenome_frame_release(&own, mem);
		return finish(out, state_of((enum kgenome_frame_state)f->state));
	}
	memset(&bud, 0, sizeof bud);
	bud.max_bytes = src.max_bytes;
	if (rq->keep) {
		label_bytes = (size_t)f->cfg.n_all * sizeof *label;
		label = kgenome_cfg_alloc(mem, label_bytes);
		if (!label) {
			kgenome_frame_release(&own, mem);
			out->status = KGENOME_NOMEM;
			return finish(out, KOF_CFGSIGN_NOMEM);
		}
	}
	memset(&sq, 0, sizeof sq);
	sq.g = &f->cfg;
	sq.label = label;
	sq.budget = &bud;
	sq.mem = src.mem;
	st = kgenome_cfg_sign(&sq, &out->sign);
	out->status = kgenome_status_merge(st, f->cfg.status);
	if (st == KGENOME_NOMEM || st == KGENOME_OVER_BUDGET) {
		const enum kof_cfgsign_state s = st == KGENOME_NOMEM ? KOF_CFGSIGN_NOMEM : KOF_CFGSIGN_OVER_BUDGET;

		kgenome_cfg_release(mem, label, label_bytes);
		kgenome_frame_release(&own, mem);
		memset(&out->sign, 0, sizeof out->sign);
		return finish(out, s);
	}
	memset(&aq, 0, sizeof aq);
	aq.min_blk = rq->floor ? rq->floor : KGENOME_CFG_ANCHOR_MIN;
	{
		const int pass = kgenome_cfg_anchor(&f->cfg, &aq);

		if (rq->keep) {
			/* the viewer's: the instructions, the graph and the labels go to the caller (kof_cfgsign_release) */
			out->in = own.in;
			out->in_bytes_ = own.in_bytes_;
			out->g = own.cfg;
			out->label = label;
			out->label_bytes_ = label_bytes;
		} else {
			kgenome_frame_release(&own, mem);       /* a no-op when the frame is the cache's */
		}
		return finish(out, pass ? KOF_CFGSIGN_SIGNED : KOF_CFGSIGN_BELOW_FLOOR);
	}
}
